#!/usr/bin/env python3
"""Embed the sampled stimuli in a standalone Web Audio listening test."""
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent
stimuli = json.loads((BASE / "stimuli.json").read_text())
payload = json.dumps(stimuli).replace("</", "<\\/")
page = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rhythmic surprise listening test</title>
<style>
  body { max-width: 650px; margin: 3rem auto; padding: 0 1rem; font: 18px/1.5 system-ui; background: #15171a; color: #eee; }
  .card { background: #22262b; border-radius: 14px; padding: 2rem; }
  button { font: inherit; padding: .65rem 1rem; margin: .3rem; border: 0; border-radius: 8px; cursor: pointer; }
  #play { background: #78a9ff; color: #111; }
  .rating { width: 3.2rem; font-size: 1.3rem; }
  .muted { color: #abb2ba; }
  #finish { display: none; }
</style>
</head>
<body>
<div class="card">
  <h1>Rhythmic surprise</h1>
  <div id="test">
    <p>Play each rhythm and rate <strong>how surprising the final click feels</strong>. The preceding clicks establish the context. You may replay before rating.</p>
    <p class="muted">1 = completely expected · 5 = very surprising. Headphones recommended. There are no right answers.</p>
    <p id="progress"></p>
    <button id="play">Play rhythm (Space)</button>
    <div id="buttons" aria-label="Surprise rating">
      <button class="rating" data-value="1">1</button>
      <button class="rating" data-value="2">2</button>
      <button class="rating" data-value="3">3</button>
      <button class="rating" data-value="4">4</button>
      <button class="rating" data-value="5">5</button>
    </div>
  </div>
  <div id="finish">
    <h2>Thank you</h2>
    <p>Download the ratings and place the JSON file in the <code>rhythm-lab</code> directory for analysis.</p>
    <button id="download">Download ratings</button>
  </div>
</div>
<script>
const stimuli = __STIMULI__;
let index = 0;
let audio;
const ratings = [];
const test = document.getElementById('test');
const finish = document.getElementById('finish');
const progress = document.getElementById('progress');

function play() {
  if (audio) audio.close();
  audio = new (window.AudioContext || window.webkitAudioContext)();
  const secondsPerBeat = 60 / 90;
  const start = audio.currentTime + .12;
  let onset = start;
  const times = [onset];
  for (const interval of stimuli[index].intervals) {
    onset += interval * secondsPerBeat;
    times.push(onset);
  }
  for (const time of times) {
    const oscillator = audio.createOscillator();
    const gain = audio.createGain();
    oscillator.type = 'sine';
    oscillator.frequency.value = 700;
    gain.gain.setValueAtTime(.25, time);
    gain.gain.exponentialRampToValueAtTime(.001, time + .07);
    oscillator.connect(gain).connect(audio.destination);
    oscillator.start(time);
    oscillator.stop(time + .08);
  }
}

function show() {
  if (index >= stimuli.length) {
    test.style.display = 'none';
    finish.style.display = 'block';
    return;
  }
  progress.textContent = `Clip ${index + 1} of ${stimuli.length}`;
}

function rate(value) {
  ratings.push({id: stimuli[index].id, rating: value});
  index++;
  show();
}

document.getElementById('play').addEventListener('click', play);
document.querySelectorAll('.rating').forEach(button => {
  button.addEventListener('click', () => rate(Number(button.dataset.value)));
});
document.addEventListener('keydown', event => {
  if (event.code === 'Space') { event.preventDefault(); play(); }
  if (/^[1-5]$/.test(event.key)) rate(Number(event.key));
});
document.getElementById('download').addEventListener('click', () => {
  const byId = Object.fromEntries(stimuli.map(s => [s.id, s]));
  const output = {
    tempo_bpm: 90,
    ratings: ratings.map(r => ({...byId[r.id], rating: r.rating}))
  };
  const blob = new Blob([JSON.stringify(output, null, 2)], {type: 'application/json'});
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = 'surprise_ratings.json';
  link.click();
});
show();
</script>
</body>
</html>
""".replace("__STIMULI__", payload)
output = BASE / "surprise_ratings.html"
output.write_text(page)
print(f"Wrote {output} with {len(stimuli)} clips")
