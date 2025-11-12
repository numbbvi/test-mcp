const ARRAY_METHODS = ['forEach', 'map', 'filter', 'find', 'some', 'every', 
                       'reduce', 'reduceRight', 'flatMap'];

const TAINT_SOURCE_LIST = [
    'req.body', 'req.query', 'req.params', 'req.headers',
    'document.getElementById', 'window.location', 'location.search',
    'process.env', 'fs.readFile', 'fs.readFileSync',
    'JSON.parse', 'eval', 'new Function',
    'localStorage.getItem', 'sessionStorage.getItem',
    'crypto.randomBytes', 'Math.random',
    // 추가된 사용자 입력 소스들
    'args', 'args.', 'req', 'request', 'input', 'user', 'param', 'query', 'body', 'data', 'payload',
    // GitHub CLI 특화 사용자 입력 패턴들
    'args.title', 'args.emoji', 'args.issue_number', 'args.repo', 'args.body', 'args.labels', 'args.assignees', 'args.state',
    'titleWithEmoji', 'bodyFlag', 'labelsFlag', 'assigneesFlag', 'owner', 'repo',
    // 일반적인 사용자 입력 패턴들
    'userInput', 'userCommand', 'command', 'cmd', 'filename', 'filepath', 'path', 'url', 'endpoint',
    'search', 'filter', 'query', 'sort', 'order', 'content', 'message', 'text'
];

const TAINT_SINK_LIST = [
    'exec', 'spawn', 'execFile', 'child_process',
    'readFile', 'readFileSync', 'createReadStream',
    'fs.readFile', 'fs.readFileSync', 'fs.createReadStream',
    'writeFile', 'writeFileSync', 'appendFile',
    'fs.writeFile', 'fs.writeFileSync', 'fs.appendFile',
    'unlink', 'unlinkSync', 'rm', 'rmSync',
    'fs.unlink', 'fs.unlinkSync', 'fs.rm', 'fs.rmSync',
    'http.request', 'fetch', 'axios', 'request',
    'console.log', 'console.error', 'console.warn',
    'document.write', 'innerHTML', 'outerHTML',
    'eval', 'Function', 'setTimeout', 'setInterval',
    // execAsync 래퍼 함수들 추가
    'execAsync', 'execPromise', 'runCommand', 'executeCommand', 'runScript', 'executeScript'
];

module.exports = {
    ARRAY_METHODS,
    TAINT_SOURCE_LIST,
    TAINT_SINK_LIST
};