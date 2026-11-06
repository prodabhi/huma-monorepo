// A real computer-use agent as a generator (harness.mjs computer_use_agent): Claude with the computer tool, seeing the
// write page through screenshots and acting on it through Playwright (mouse, keyboard, typing). Needs
// ANTHROPIC_API_KEY. The agent is asked to write a short essay in the editor; whatever it types is the session.
const MODEL = process.env.HUMA_EVAL_MODEL ?? 'claude-sonnet-5-5';
const STEPS = 40;

export async function computerUseAgent({ page, essay }) {
  const key = process.env.ANTHROPIC_API_KEY;
  if (!key) return 'skipped: ANTHROPIC_API_KEY is not set';
  const { width, height } = page.viewportSize();
  const tool = { type: 'computer_20250124', name: 'computer', display_width_px: width, display_height_px: height };
  const messages = [{ role: 'user', content: essay }];
  for (let step = 0; step < STEPS; step++) {
    const response = await fetch('https://api.anthropic.com/v1/messages', { method: 'POST',
      headers: { 'x-api-key': key, 'anthropic-version': '2023-06-01', 'anthropic-beta': 'computer-use-2025-01-24', 'content-type': 'application/json' },
      body: JSON.stringify({ model: MODEL, max_tokens: 2048, tools: [tool], messages }) });
    if (!response.ok) return 'skipped: the API answered ' + response.status + ' ' + (await response.text()).slice(0, 200);
    const reply = await response.json();
    messages.push({ role: 'assistant', content: reply.content });
    const uses = reply.content.filter(block => block.type === 'tool_use');
    if (!uses.length || reply.stop_reason === 'end_turn') return 'typed';
    const results = [];
    for (const use of uses) {
      const a = use.input, out = { type: 'tool_result', tool_use_id: use.id };
      try {
        if (a.action === 'screenshot') { /* below */ }
        else if (a.action === 'left_click') await page.mouse.click(a.coordinate[0], a.coordinate[1]);
        else if (a.action === 'double_click') await page.mouse.dblclick(a.coordinate[0], a.coordinate[1]);
        else if (a.action === 'mouse_move') await page.mouse.move(a.coordinate[0], a.coordinate[1]);
        else if (a.action === 'type') await page.keyboard.type(a.text, { delay: 12 });
        else if (a.action === 'key') await page.keyboard.press(a.text.replace(/^Return$/, 'Enter').replace(/\+/g, '+'));
        else if (a.action === 'scroll') await page.mouse.wheel(0, (a.scroll_direction === 'down' ? 1 : -1) * 100 * (a.scroll_amount ?? 3));
        else if (a.action === 'wait') await page.waitForTimeout(1000 * Math.min(5, a.duration ?? 1));
        const shot = await page.screenshot({ type: 'png' });
        out.content = [{ type: 'image', source: { type: 'base64', media_type: 'image/png', data: shot.toString('base64') } }];
      } catch (error) { out.content = 'Error: ' + error.message; out.is_error = true; }
      results.push(out);
    }
    messages.push({ role: 'user', content: results });
    if (await page.evaluate(() => document.getElementById('halt').open)) return 'halted';
  }
  return 'typed';
}
