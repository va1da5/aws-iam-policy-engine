const challengeStorageKey = "___activeChallenge";

export function getActiveChallenge() {
  const current = localStorage.getItem(challengeStorageKey);
  if (!current) return 1;
  return parseInt(current);
}

export function setActiveChallenge(value: number) {
  localStorage.setItem(challengeStorageKey, value.toString());
}
