const LEVELS = { debug: 0, info: 1, warn: 2, error: 3 } as const;
type Level = keyof typeof LEVELS;

let currentLevel: Level = "info";

export function setLogLevel(level: Level): void {
  currentLevel = level;
}

export function getLogLevel(): Level {
  return currentLevel;
}

function shouldLog(level: Level): boolean {
  return LEVELS[level] >= LEVELS[currentLevel];
}

export function logDebug(msg: string): void {
  if (shouldLog("debug")) process.stderr.write(`quint [debug]: ${msg}\n`);
}

export function logInfo(msg: string): void {
  if (shouldLog("info")) process.stderr.write(`quint: ${msg}\n`);
}

export function logWarn(msg: string): void {
  if (shouldLog("warn")) process.stderr.write(`quint [warn]: ${msg}\n`);
}

export function logError(msg: string): void {
  if (shouldLog("error")) process.stderr.write(`quint [error]: ${msg}\n`);
}
