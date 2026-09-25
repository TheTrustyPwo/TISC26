#!/usr/bin/env python3
"""Generate the instruction-accurate, self-contained V46 arena simulator."""

from pathlib import Path


OUT = Path(__file__).with_name("v46-lattice-viewer.html")
BOT_HEX = (
    "0000e05d3801ef050800205a00026f0be83f9b08ff3f841080ff11050000c95b"
    "001820043000605a0398840080ff9b121000405a0288b4020290d50200006f3104"
    "008f310800af310c00cf311000ef3214000f3318002f331c004f33200076452400"
    "96452800b6452c00d6453000f64634001647380036473c005647843c6004200056"
    "05020000fce0ff210440007545440095454800b5454c00d5455000f54654001547"
    "580035475c005547843c600440005505020000fce0ff2104600074456400944568"
    "00b4456c00d4457000f44674001447780034477c005447843c6004600054050200"
    "00fce0ff210400007445040094450800b4450c00d4451000f446140014471800344"
    "71c005447843c60042000d4472400d4472800d4472c00d447ac3fd347c87fd347"
    "e47fd34790ffd347acffd347000014540118210008412100022041000080c24700c"
    "0c2470000c2470040c247e4ff1f48"
)


HTML = r'''<!doctype html>
<meta charset="utf-8">
<title>V46 instruction-accurate lattice simulator</title>
<style>
  :root { color-scheme: dark; }
  body { margin: 0; background: #10151c; color: #e6edf3; font: 14px system-ui, sans-serif; }
  main { max-width: 960px; margin: 20px auto; padding: 0 16px; }
  canvas { display: block; width: min(100%, 760px); height: auto; image-rendering: pixelated; background: #151b23; }
  .row { display: flex; flex-wrap: wrap; align-items: center; gap: 10px 14px; margin: 12px 0; }
  button, select, input { font: inherit; accent-color: #59c1ff; }
  button { padding: 5px 10px; }
  code { color: #b6e3ff; }
  .legend, .muted { color: #9aa8b7; }
  #status { line-height: 1.55; }
  .processes { display: grid; grid-template-columns: repeat(4, minmax(110px, 1fr)); gap: 6px; margin: 10px 0; }
  .proc { background: #18212b; padding: 7px 9px; border-left: 4px solid #5d6875; }
  .proc.active { background: #223040; }
  @media (max-width: 580px) { .processes { grid-template-columns: repeat(2, minmax(110px, 1fr)); } }
</style>
<main>
  <h1>V46 instruction-accurate lattice</h1>
  <canvas id="arena" width="128" height="128" aria-label="64 KiB arena, one pixel per four-byte word"></canvas>
  <div class="row">
    <button id="play">Play</button>
    <button id="step">Step 1 tick</button>
    <button id="reset">Reset</button>
    <label>speed
      <select id="speed">
        <option value="1">1 tick/frame</option>
        <option value="4">4 ticks/frame</option>
        <option value="16">16 ticks/frame</option>
        <option value="64">64 ticks/frame</option>
        <option value="256">256 ticks/frame</option>
      </select>
    </label>
  </div>
  <div class="row">
    <label>battle tick <input id="ticks" type="range" min="0" max="132000" value="0"></label>
    <output id="count">0 / 132000</output>
  </div>
  <div id="status" aria-live="polite"></div>
  <div id="processes" class="processes"></div>
  <p class="legend">Gray: uploaded V46 · cyan: copied worker code · blue: four safe-bank tail stores · pink: five fixed-target tail stores · worker colors: steady lattice writes. Exactly one V46 process executes one instruction per battle tick; live processes are selected round-robin.</p>
</main>
<script>
(() => {
  'use strict';
  const PROGRAM_HEX = '__PROGRAM_HEX__';
  const BASE = 0x15400;
  const ARENA_BASE = 0x10000, ARENA_BYTES = 0x10000, WORDS = ARENA_BYTES >>> 2;
  const OP = { ADDI:1, XORI:2, ANDI:4, LW:12, SW:17, BEQ:18, JALR:21, LUI:22, AUIPC:23, PROCESS:63 };
  const PROC_COLORS = ['#e76f51', '#e9c46a', '#2a9d8f', '#a78bfa'];
  const INITIAL = '#5d6875', COPY = '#42c6d9', BANK = '#4c9be8', PIN = '#e879a8', EMPTY = '#151b23';
  const TAIL_NAMES = [
    'bank r20+0x20', 'bank r20+0x24', 'bank r20+0x28', 'bank r20+0x2c',
    'pin 0x1bfac', 'pin 0x1ffc8', 'pin 0x1ffe4', 'pin 0x17f90', 'pin 0x17fac'
  ];
  const bytes = new Uint8Array(PROGRAM_HEX.match(/../g).map(x => parseInt(x, 16)));
  const PROGRAM = [];
  for (let i = 0; i < bytes.length; i += 4) {
    PROGRAM.push((bytes[i] | bytes[i+1] << 8 | bytes[i+2] << 16 | bytes[i+3] << 24) >>> 0);
  }
  if (PROGRAM.length !== 86) throw new Error(`expected 86 words, got ${PROGRAM.length}`);

  const canvas = document.getElementById('arena'), ctx = canvas.getContext('2d');
  const slider = document.getElementById('ticks'), count = document.getElementById('count');
  const status = document.getElementById('status'), procPanel = document.getElementById('processes');
  const play = document.getElementById('play'), speed = document.getElementById('speed');
  let state, running = false, raf = 0;

  function signed(value, bits) {
    const shift = 32 - bits;
    return (value << shift) >> shift;
  }
  function arenaIndex(address) { return (((address - ARENA_BASE) & 0xffff) >>> 2); }
  function arenaAddress(address) { return ARENA_BASE + ((address - ARENA_BASE) & 0xffff); }
  function readWord(s, address) { return s.memory[arenaIndex(address)] >>> 0; }
  function writeWord(s, address, value, kind, processId) {
    const i = arenaIndex(address);
    s.memory[i] = value >>> 0;
    s.paint[i] = kind;
    s.owner[i] = processId;
  }
  function makeProcess(id, pc, regs) {
    return { id, pc: arenaAddress(pc), regs: new Uint32Array(regs), alive: true, instructions: 0, stores: 0 };
  }
  function freshState() {
    const s = {
      tick: 0, memory: new Uint32Array(WORDS), paint: new Uint8Array(WORDS),
      owner: new Int8Array(WORDS), processes: [], cursor: 0, active: -1,
      last: 'ready', tailExecuted: 0, latticeStores: 0
    };
    s.owner.fill(-1);
    for (let i = 0; i < PROGRAM.length; i++) {
      const j = arenaIndex(BASE + i * 4);
      s.memory[j] = PROGRAM[i]; s.paint[j] = 1;
    }
    s.processes.push(makeProcess(0, BASE, new Uint32Array(32)));
    return s;
  }
  function describe(pc, word) {
    const index = ((pc - BASE) >>> 2);
    if (index >= 68 && index <= 76) return `tail ${index - 67}/9: ${TAIL_NAMES[index - 68]}`;
    if (index === 77) return 'root jumps into local worker';
    const op = word >>> 26;
    if (op === OP.PROCESS) return 'spawn child at r10';
    if (op === OP.SW) return index >= 78 ? 'worker lattice store' : 'loader copy store';
    if (index >= 78 && index <= 85) return `worker instruction ${index - 77}/8`;
    return index >= 0 && index < 78 ? `loader instruction ${index + 1}/78` : 'copied worker instruction';
  }
  function executeOne(s) {
    if (!s.processes.length) return;
    s.cursor %= s.processes.length;
    const p = s.processes[s.cursor];
    s.active = p.id;
    const pc = p.pc, word = readWord(s, pc), op = word >>> 26;
    const rd = (word >>> 21) & 31, rs1 = (word >>> 16) & 31, rs2 = (word >>> 11) & 31;
    const imm16 = signed(word & 0xffff, 16), imm21 = signed(word & 0x1fffff, 21);
    const next = arenaAddress(pc + 4);
    let nextPc = next, event = describe(pc, word);
    p.regs[0] = 0;

    if (op === 0) {
      const funct = word & 0x7ff;
      if (funct === 1) p.regs[rd] = (p.regs[rs1] + p.regs[rs2]) >>> 0;
      else if (funct === 2) p.regs[rd] = (p.regs[rs1] ^ p.regs[rs2]) >>> 0;
      else if (funct === 3) p.regs[rd] = (p.regs[rs1] | p.regs[rs2]) >>> 0;
      else if (funct === 4) p.regs[rd] = (p.regs[rs1] & p.regs[rs2]) >>> 0;
      else if (funct === 0x108) p.regs[rd] = p.regs[rs2] ? (p.regs[rs1] % p.regs[rs2]) >>> 0 : p.regs[rs1];
    } else if (op === OP.ADDI) p.regs[rd] = (p.regs[rs1] + imm16) >>> 0;
    else if (op === OP.XORI) p.regs[rd] = (p.regs[rs1] ^ (imm16 >>> 0)) >>> 0;
    else if (op === OP.ANDI) p.regs[rd] = (p.regs[rs1] & (imm16 >>> 0)) >>> 0;
    else if (op === OP.LUI) p.regs[rd] = ((word & 0x1fffff) << 11) >>> 0;
    else if (op === OP.AUIPC) p.regs[rd] = (pc + ((word & 0x1fffff) << 11)) >>> 0;
    else if (op === OP.LW) p.regs[rd] = readWord(s, p.regs[rs1] + imm16);
    else if (op === OP.SW) {
      const address = arenaAddress(p.regs[rs1] + imm16);
      const loaderIndex = ((pc - BASE) >>> 2);
      let kind = 2;
      if (loaderIndex >= 68 && loaderIndex <= 71) kind = 3;
      else if (loaderIndex >= 72 && loaderIndex <= 76) kind = 4;
      else if (loaderIndex < 68) kind = 2;
      else { kind = 5; s.latticeStores++; }
      writeWord(s, address, p.regs[rd], kind, p.id);
      p.stores++;
      if (loaderIndex >= 68 && loaderIndex <= 76) s.tailExecuted++;
      event += ` → 0x${address.toString(16)}`;
    } else if (op === OP.BEQ) {
      if (p.regs[rd] === 0) nextPc = arenaAddress(pc + imm21);
    } else if (op === OP.JALR) {
      const target = arenaAddress(p.regs[rs1] + imm16);
      p.regs[rd] = next;
      nextPc = target;
    } else if (op === OP.PROCESS) {
      if ((word & 0x1fffff) === 2 && s.processes.length < 4) {
        const child = makeProcess(s.processes.length, p.regs[10], p.regs);
        s.processes.push(child);
        event += ` → P${child.id} at 0x${child.pc.toString(16)}`;
      }
    }
    p.regs[0] = 0;
    p.pc = nextPc;
    p.instructions++;
    s.tick++;
    s.last = `P${p.id}: ${event}`;
    s.cursor = (s.cursor + 1) % s.processes.length;
  }
  function runTo(target) {
    if (target < state.tick) state = freshState();
    while (state.tick < target) executeOne(state);
  }
  function colorFor(i) {
    const kind = state.paint[i];
    if (kind === 1) return INITIAL;
    if (kind === 2) return COPY;
    if (kind === 3) return BANK;
    if (kind === 4) return PIN;
    if (kind === 5) return PROC_COLORS[Math.max(0, state.owner[i]) % 4];
    return EMPTY;
  }
  function render() {
    for (let i = 0; i < WORDS; i++) {
      ctx.fillStyle = colorFor(i);
      ctx.fillRect(i % 128, Math.floor(i / 128), 1, 1);
    }
    slider.value = Math.min(state.tick, Number(slider.max));
    count.value = `${state.tick} / ${slider.max}`;
    const template = BASE + 78 * 4, r27 = template ^ 0x200, local = r27 & ~0x7f;
    status.innerHTML = `<strong>tick ${state.tick}</strong> · next P${state.cursor} · live ${state.processes.length}/4 · tail ${state.tailExecuted}/9 · lattice stores ${state.latticeStores}<br><code>${state.last}</code><br><span class="muted">load 0x${BASE.toString(16)} · sanctuary 0x${local.toString(16)} · one process instruction per tick</span>`;
    procPanel.innerHTML = state.processes.map(p => {
      const cls = p.id === state.active ? 'proc active' : 'proc';
      return `<div class="${cls}" style="border-left-color:${PROC_COLORS[p.id]}"><strong>P${p.id}</strong> PC <code>0x${p.pc.toString(16)}</code><br><span class="muted">${p.instructions} instructions · ${p.stores} stores</span></div>`;
    }).join('');
  }
  function frame() {
    if (running) {
      const n = Number(speed.value);
      for (let i = 0; i < n && state.tick < Number(slider.max); i++) executeOne(state);
      if (state.tick >= Number(slider.max)) { running = false; play.textContent = 'Play'; }
      render();
    }
    raf = requestAnimationFrame(frame);
  }
  slider.addEventListener('input', () => { runTo(Number(slider.value)); render(); });
  document.getElementById('step').addEventListener('click', () => { running = false; play.textContent = 'Play'; executeOne(state); render(); });
  document.getElementById('reset').addEventListener('click', () => { running = false; play.textContent = 'Play'; state = freshState(); render(); });
  play.addEventListener('click', () => { running = !running; play.textContent = running ? 'Pause' : 'Play'; });
  state = freshState();
  render();
  raf = requestAnimationFrame(frame);
})();
</script>'''


def main() -> None:
    raw = bytes.fromhex(BOT_HEX)
    assert len(raw) == 344
    OUT.write_text(HTML.replace("__PROGRAM_HEX__", BOT_HEX), encoding="utf-8")
    print(OUT)


if __name__ == "__main__":
    main()
