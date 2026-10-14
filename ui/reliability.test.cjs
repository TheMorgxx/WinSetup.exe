const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const { test } = require('node:test');
const ts = require('typescript');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, 'app.ts'), 'utf8');
const tree = ts.createSourceFile('app.ts', source, ts.ScriptTarget.Latest, true);
const names = new Set(['esc', 'btn', 'status', 'taskResults', 'progress']);
const pieces = [];
for (const node of tree.statements) {
  if (ts.isFunctionDeclaration(node) && names.has(node.name?.text)) pieces.push(node.getText(tree));
  if (ts.isVariableStatement(node) && node.declarationList.declarations.some(d => names.has(d.name.getText(tree)))) pieces.push(node.getText(tree));
}
assert.equal(pieces.length, names.size);
const compiled = ts.transpileModule(pieces.join('\n'), {compilerOptions: {target: ts.ScriptTarget.ES2020}}).outputText;
function page(tasks, overrides = {}, opened = []) {
  const context = vm.createContext({
    run: {id: 'fixture', active: false, paused: false, finished: false, log: [], tasks, ...overrides},
    document: {querySelectorAll: () => opened.map(id => ({getAttribute: () => String(id)}))}
  });
  vm.runInContext(compiled, context);
  return expression => vm.runInContext(expression, context);
}
const task = (status, id = 0) => ({id, status, name: 'Программа', detail: 'Подробности', action: {kind: 'Program'}});
test('a completed pass with unconfirmed tasks is not shown as an interrupted run', () => {
  const evaluate = page([task('succeeded'), task('needs_verification', 1), task('failed', 2)]);
  const html = evaluate('progress()');
  assert.match(html, /3 из 3 задач/);
  assert.match(html, /Завершено с замечаниями/);
  assert.match(html, /без повторного запуска установщиков/);
  assert.doesNotMatch(html, /Выполнение остановлено/);
});
test('an actual stopped run is not mislabeled completed', () => {
  const evaluate = page([task('succeeded'), task('pending', 1)]);
  assert.match(evaluate('progress()'), /Выполнение остановлено/);
});
test('task details escape installer output and retain expanded rows', () => {
  const t = task('needs_verification', 7);
  t.name = '<img src=x onerror=bad>';
  t.detail = '<script>bad()</script>';
  const html = page([t], {}, [7])('taskResults()');
  assert.match(html, /Нужна проверка/);
  assert.match(html, /data-task-detail="7" open/);
  assert.match(html, /&lt;script&gt;/);
  assert.doesNotMatch(html, /<script>|<img /);
});
test('restore-point consent remains visible and separate from normal continuation', () => {
  const t = task('awaiting_confirm');
  const html = page([t])('progress()');
  assert.match(html, /Продолжить без точки восстановления/);
  assert.match(html, /ожидают подтверждения/);
});
