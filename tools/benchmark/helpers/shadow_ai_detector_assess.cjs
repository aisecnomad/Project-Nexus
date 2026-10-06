// Runs shadow-ai-detector's own assessEvent() over benchmark traffic events.
// Usage: node shadow_ai_detector_assess.cjs <shadow-ai-detector dist dir> <events.json>
// The sanctioned list is empty, so every catalog match is reported.
'use strict';
const fs = require('fs');
const path = require('path');

const [dist, eventsPath] = process.argv.slice(2);
const { assessEvent } = require(path.join(path.resolve(dist), 'governance', 'risk-scorer.js'));
const events = JSON.parse(fs.readFileSync(eventsPath, 'utf8'));
const out = events.map((event) => {
  const a = assessEvent(event, new Set());
  return {
    eventId: a.eventId,
    matched: a.matched,
    endpointId: a.endpointId,
    riskTier: a.riskTier,
    riskScore: a.riskScore,
  };
});
process.stdout.write(JSON.stringify(out));
