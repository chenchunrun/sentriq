# Copyright 2026 CCR <chenchunrun@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Single-device RLCD fine-tuning of Laya on the security triage dataset.

Adapted from the official notebook
(notesbooks/laya_finetune_typed_decisions_2xT4_kaggle.ipynb in
NandhaKishorM/laya) for Apple Silicon / CPU: no DDP, no CUDA GradScaler,
optional bf16 autocast on MPS. Same algorithm: GRPO-style noise exploration
with proper scoring rewards + soft cross-entropy guidance, dual learning
rates (encoder 2.5e-5 / head 1e-4), cosine schedule, per-epoch rolling
checkpoints, and post-training temperature calibration.

Usage:
    PYTHONPATH=services venv/bin/python services/triage_engine/finetune/train.py \
        --train-data services/triage_engine/finetune/data/train.jsonl \
        --output-dir services/triage_engine/models/laya-security-v1
"""

import argparse
import json
import os
import random
import sys
import time
from pathlib import Path

import torch
from safetensors.torch import load_file, save_file
from transformers import AutoTokenizer

from laya.agent import _fix_tokenizer_config
from laya.common import QTYPES, build_model, build_sequence, proper_reward, render_options


# --------------------------------------------------------------------- data
def build_training_item(tok, cfg, state, question, gold_q):
    qtype = question["type"]
    crit = question.get("criteria", {})
    if qtype == "choice":
        keys = list(crit.keys())
        target = [gold_q["probabilities"].get(k, 0.0) for k in keys]
    elif qtype == "noul":
        target = [gold_q["probabilities"].get("false", 0.5), gold_q["probabilities"].get("true", 0.5)]
    else:  # score
        n_levels = len(crit) if isinstance(crit, list) else 5
        target = [gold_q["probabilities"].get(str(i), 0.0) for i in range(n_levels)]
    total = sum(target)
    target = [v / total for v in target] if total > 0 else [1.0 / len(target)] * len(target)
    label = target.index(max(target))
    k = len(render_options({"t": qtype, "crit": crit}))
    seq, markers = build_sequence(
        tok, state, {"t": qtype, "ins": question["instructions"], "crit": crit},
        cfg["max_len"], cfg["head_max_len"],
    )
    if len(markers) != k:
        return None
    return {"ids": seq, "markers": markers, "qtype": QTYPES[qtype], "target": target, "label": label}


def load_items(tok, cfg, jsonl_path):
    items = []
    with open(jsonl_path, encoding="utf-8") as fh:
        for line in fh:
            row = json.loads(line)
            state = json.loads(row["state"])
            questions = json.loads(row["questions"])
            gold = json.loads(row["gold"])
            for qid, question in questions.items():
                if qid in gold:
                    item = build_training_item(tok, cfg, state, question, gold[qid])
                    if item:
                        items.append(item)
    return items


def collate(items, pad_id):
    n, length = len(items), max(len(it["ids"]) for it in items)
    kmax = max(len(it["markers"]) for it in items)
    ids = torch.full((n, length), pad_id, dtype=torch.long)
    att = torch.zeros((n, length), dtype=torch.long)
    mpos = torch.zeros((n, kmax), dtype=torch.long)
    mmask = torch.zeros((n, kmax), dtype=torch.bool)
    target = torch.zeros((n, kmax), dtype=torch.float32)
    for i, it in enumerate(items):
        ids[i, : len(it["ids"])] = torch.tensor(it["ids"])
        att[i, : len(it["ids"])] = 1
        k = len(it["markers"])
        mpos[i, :k] = torch.tensor(it["markers"])
        mmask[i, :k] = True
        target[i, : len(it["target"])] = torch.tensor(it["target"], dtype=torch.float32)
    return ids, att, mpos, mmask, target, torch.tensor([it["qtype"] for it in items])


# ------------------------------------------------------------ temperature fit
def fit_one_temp(sel):
    if len(sel) < 10:
        return 1.0
    kmax = max(len(z) for z, _ in sel)
    Z = torch.full((len(sel), kmax), -1e4)
    T = torch.zeros((len(sel), kmax))
    for i, (z, t) in enumerate(sel):
        Z[i, : len(z)] = torch.tensor(z)
        T[i, : len(t)] = torch.tensor(t, dtype=torch.float32)
    log_t = torch.zeros(1, requires_grad=True)
    opt = torch.optim.LBFGS([log_t], lr=0.1, max_iter=100)

    def closure():
        opt.zero_grad()
        loss = -(T * torch.log_softmax(Z / log_t.exp(), -1)).sum(-1).mean()
        loss.backward()
        return loss

    opt.step(closure)
    return float(torch.clamp(log_t.exp(), 0.1, 10.0).item())


# --------------------------------------------------------------------- train
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-dir", default=None, help="base checkpoint dir (default: cached typed-decisions)")
    parser.add_argument("--train-data", default=str(Path(__file__).parent / "data" / "train.jsonl"))
    parser.add_argument("--output-dir", default=str(Path(__file__).resolve().parents[1] / "models" / "laya-security-v1"))
    parser.add_argument("--epochs", type=int, default=4)
    parser.add_argument("--micro-batch", type=int, default=8)
    parser.add_argument("--grad-accum", type=int, default=4)
    parser.add_argument("--group-size", type=int, default=4)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    torch.manual_seed(args.seed)
    random.seed(args.seed)

    device = torch.device("mps") if torch.backends.mps.is_available() else torch.device("cpu")
    print(f"device: {device}")

    model_dir = args.model_dir
    if model_dir is None:
        from huggingface_hub import snapshot_download

        model_dir = snapshot_download(
            "convaiinnovations/laya", allow_patterns=["typed-decisions/*", "typed-decisions/**"]
        )
        model_dir = os.path.join(model_dir, "typed-decisions")
    _fix_tokenizer_config(model_dir)
    print(f"base checkpoint: {model_dir}")

    with open(os.path.join(model_dir, "rl_agent_config.json")) as fh:
        cfg = json.load(fh)
    cfg["gradient_checkpointing"] = True
    cfg["max_tokens_per_batch"] = 4096
    cfg["max_len"] = 1024
    cfg["head_max_len"] = 256

    tok = AutoTokenizer.from_pretrained(os.path.join(model_dir, "tokenizer"))
    items = load_items(tok, cfg, args.train_data)
    print(f"training items: {len(items)}")

    model = build_model(cfg, encoder_dir=os.path.join(model_dir, "encoder"))
    weights = load_file(os.path.join(model_dir, "model.safetensors"))
    model.load_state_dict(weights, strict=True)
    try:
        model.encoder.gradient_checkpointing_enable(gradient_checkpointing_kwargs={"use_reentrant": False})
        model.head_checkpointing = True
    except Exception as exc:  # noqa: BLE001 - checkpointing is an optimization, not a requirement
        print(f"gradient checkpointing unavailable ({exc}); continuing without")
    model.to(device)
    model.train()

    enc_params = [p for n, p in model.named_parameters() if "encoder." in n]
    head_params = [p for n, p in model.named_parameters() if "encoder." not in n]
    optimizer = torch.optim.AdamW(
        [{"params": enc_params, "lr": 2.5e-5}, {"params": head_params, "lr": 1e-4}],
        weight_decay=0.01,
    )
    total_updates = max(1, (len(items) // (args.micro_batch * args.grad_accum)) * args.epochs)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=total_updates, eta_min=1e-6)

    use_amp = device.type == "mps"
    if use_amp:
        try:
            probe = torch.arange(4, device=device)
            with torch.autocast("mps", dtype=torch.bfloat16):
                _ = probe.float().mean()
        except Exception:  # noqa: BLE001
            use_amp = False
    print(f"bf16 autocast: {use_amp}")

    os.makedirs(args.output_dir, exist_ok=True)
    t0 = time.time()
    sigma_start, sigma_end = 0.4, 0.1

    for epoch in range(args.epochs):
        random.seed(args.seed + epoch)
        random.shuffle(items)
        optimizer.zero_grad(set_to_none=True)
        epoch_loss, n_batches, accum = 0.0, 0, 0
        progress = epoch / max(1, args.epochs - 1)
        sigma = sigma_start + (sigma_end - sigma_start) * progress

        for b_idx in range(0, len(items), args.micro_batch):
            chunk = items[b_idx : b_idx + args.micro_batch]
            if not chunk:
                continue
            ids, att, mpos, mmask, target, qtype = collate(chunk, tok.pad_token_id)

            def forward():
                return model(ids.to(device), att.to(device), mpos.to(device),
                             mmask.to(device), qtype.to(device))

            if use_amp:
                with torch.autocast("mps", dtype=torch.bfloat16):
                    logits, _ = forward()
            else:
                logits, _ = forward()
            logits = logits.float()

            mask = mmask.to(device)
            k = mask.sum(-1, keepdim=True).float()
            target_d = target.to(device)

            eps = torch.randn((args.group_size,) + logits.shape, device=device) * sigma * mask
            eps = (eps - eps.sum(-1, keepdim=True) / k) * mask
            z = logits.detach().unsqueeze(0) + eps
            q = torch.softmax(z.masked_fill(~mask, -1e4), -1)

            with torch.no_grad():
                r = proper_reward(q, target_d.unsqueeze(0), qtype.to(device), mask, w_sph=0.75, w_rps=1.0)
                adv = r - r.mean(0, keepdim=True)
                adv = adv / (adv.std() + 1e-6)

            logp = -(((z - logits.unsqueeze(0)) ** 2) * mask).sum(-1) / (2 * sigma**2)
            loss_rl = -(adv * logp).mean()
            loss_ce = -(target_d * torch.log_softmax(logits.masked_fill(~mask, -1e4), -1)).sum(-1).mean()
            loss = (loss_rl + 1.0 * loss_ce) / args.grad_accum

            loss.backward()
            accum += 1
            if accum % args.grad_accum == 0 or (b_idx + args.micro_batch) >= len(items):
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                optimizer.step()
                scheduler.step()
                optimizer.zero_grad(set_to_none=True)

            epoch_loss += loss.item() * args.grad_accum
            n_batches += 1
            if n_batches % 25 == 0:
                print(
                    f"  epoch {epoch + 1}/{args.epochs} | step {n_batches} | "
                    f"loss {loss.item() * args.grad_accum:.4f} | reward {r.mean().item():.3f} | "
                    f"lr {scheduler.get_last_lr()[0]:.2e} | {time.time() - t0:.0f}s",
                    flush=True,
                )

        print(f"=== epoch {epoch + 1}/{args.epochs} done in {time.time() - t0:.1f}s | "
              f"avg loss {epoch_loss / max(1, n_batches):.4f} ===", flush=True)

        ckpt = os.path.join(args.output_dir, "checkpoint_latest")
        os.makedirs(ckpt, exist_ok=True)
        save_file({k: v.half().contiguous().cpu() for k, v in model.state_dict().items()},
                  os.path.join(ckpt, "model.safetensors"))
        model.encoder.config.save_pretrained(os.path.join(ckpt, "encoder"))
        tok.save_pretrained(os.path.join(ckpt, "tokenizer"))
        with open(os.path.join(ckpt, "checkpoint_meta.json"), "w") as fh:
            json.dump({"epoch": epoch + 1, "total_epochs": args.epochs,
                       "avg_loss": epoch_loss / max(1, n_batches)}, fh, indent=2)

    # post-training temperature calibration
    print("fitting calibration temperatures...", flush=True)
    model.eval()
    calib = items[::15][:400]
    calib_preds = []
    with torch.no_grad():
        for c_idx in range(0, len(calib), 16):
            sub = calib[c_idx : c_idx + 16]
            ids, att, mpos, mmask, _, qtype = collate(sub, tok.pad_token_id)
            logits, _ = model(ids.to(device), att.to(device), mpos.to(device),
                              mmask.to(device), qtype.to(device))
            l_np = logits.float().cpu().numpy()
            for r_i, it in enumerate(sub):
                calib_preds.append((it["qtype"], l_np[r_i, : len(it["markers"])], it["target"]))

    temps = [1.2, 1.2, 1.2]
    try:
        for qt in range(3):
            sel = [(z, t) for q_t, z, t in calib_preds if q_t == qt]
            if sel:
                temps[qt] = fit_one_temp(sel)
        print("temperatures (choice, score, noul):", [round(t, 3) for t in temps])
    except Exception as exc:  # noqa: BLE001
        print("temperature fitting fallback:", exc)

    save_file({k: v.half().contiguous().cpu() for k, v in model.state_dict().items()},
              os.path.join(args.output_dir, "model.safetensors"))
    model.encoder.config.save_pretrained(os.path.join(args.output_dir, "encoder"))
    tok.save_pretrained(os.path.join(args.output_dir, "tokenizer"))
    cfg["fine_tuned"] = True
    cfg["model_name"] = "laya-security-v1"
    cfg["temperature"] = temps
    with open(os.path.join(args.output_dir, "rl_agent_config.json"), "w") as fh:
        json.dump(cfg, fh, indent=2)
    print(f"saved fine-tuned model to {args.output_dir} in {time.time() - t0:.1f}s total")


if __name__ == "__main__":
    main()
