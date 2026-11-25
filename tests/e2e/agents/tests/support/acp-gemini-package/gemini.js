#!/usr/bin/env node
// The main file of the script package that stands in for Gemini CLI in the cases of ACP mode.
// The interpreter stand-in does not run it. It starts as `<interpreter> gemini.js --acp`, takes the
// folder of this file as the package folder, and reads `chunk.js` from that folder when its script
// says so, after the first permission request is answered, as the real main file imports a chunk
// only when it first needs it.
