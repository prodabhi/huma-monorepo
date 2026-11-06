import test from 'node:test';
import assert from 'node:assert/strict';
import { ruleIssues } from '../write/grammar.mjs';

const fixes = text => ruleIssues(text).map(issue => [text.slice(issue.start, issue.end), issue.fixes[0]]);

test('the Mac’s exact rules: a lone lowercase i, a word twice, a lowercase sentence start', () => {
  assert.deepEqual(fixes('i think so. the end and and more.'), [['i', 'I'], ['and and', 'and'], ['the', 'The']]);
  // Not after an abbreviation or an initial, and not "iPhone", "e.g." or a web address.
  assert.deepEqual(fixes('Dr. smith met J. doe. iPhone owners e.g. agree. www.huma.social works.'), []);
  // "had had" and "that that" can be right.
  assert.deepEqual(fixes('She had had enough. I know that that works.'), []);
  assert.deepEqual(fixes('It works! then it stops? yes it does.'), [['then', 'Then'], ['yes', 'Yes']]);
});
