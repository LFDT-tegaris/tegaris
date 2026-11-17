// Policy evaluation follows SPDX 2.3 operator precedence. It does not establish
// contribution rights, validate the SPDX registry, or approve redistribution.
const dispositions = ['ALLOW', 'REVIEW', 'UNQUALIFIED', 'DENY'];
const fields = [
  'allowLicenseIdentifiers',
  'reviewLicenseIdentifiers',
  'unqualifiedLicenseIdentifiers',
];
const canonical = (value) =>
  value
    .trim()
    .replace(/[ \t]+/gu, ' ')
    .toLowerCase();

function invalidExpression() {
  throw new SyntaxError('Invalid license expression');
}

function tokenize(expression) {
  const identifier =
    /(?:DocumentRef-[A-Za-z0-9.-]+:)?LicenseRef-[A-Za-z0-9.-]+|[A-Za-z0-9][A-Za-z0-9.-]*\+?|[()]/y;
  const tokens = [];
  let offset = 0;
  while (offset < expression.length) {
    if (/[ \t]/u.test(expression[offset])) {
      offset++;
      continue;
    }
    identifier.lastIndex = offset;
    const match = identifier.exec(expression);
    if (!match) invalidExpression();
    tokens.push({ value: match[0], start: offset, end: identifier.lastIndex });
    offset = identifier.lastIndex;
  }
  return tokens;
}

export function classifyLicense(expression, policy, { legacySlash = false } = {}) {
  if (
    typeof expression !== 'string' ||
    expression.length > 4096 ||
    /[\r\n\0\v\f]/u.test(expression) ||
    !policy ||
    typeof policy !== 'object'
  )
    return 'DENY';
  const lists = fields.map((field) => policy[field] ?? []);
  if (lists.some((list) => !Array.isArray(list) || list.some((value) => typeof value !== 'string')))
    return 'DENY';
  const allowed = lists.map((list) => new Set(list.map(canonical)));
  // Only the old two-license Cargo spelling is normalized, and only when the
  // inventory caller explicitly requests it. General SPDX input rejects '/'.
  if (legacySlash === true) {
    expression = expression.replace(
      /^[ \t]*([A-Za-z0-9][A-Za-z0-9.-]*\+?)[ \t]*\/[ \t]*([A-Za-z0-9][A-Za-z0-9.-]*\+?)[ \t]*$/u,
      '$1 OR $2',
    );
  }
  try {
    const tokens = tokenize(expression);
    for (const token of tokens) {
      if (
        ['AND', 'OR'].includes(token.value) &&
        (!/[ \t()]/u.test(expression[token.start - 1] ?? '') ||
          !/[ \t()]/u.test(expression[token.end] ?? ''))
      )
        invalidExpression();
    }
    let position = 0;
    const next = () => tokens[position]?.value;
    function identifier() {
      const token = tokens[position++];
      if (!token || ['(', ')', 'AND', 'OR', 'WITH'].includes(token.value)) invalidExpression();
      if (['unlicensed', 'noassertion', 'none', 'unknown'].includes(canonical(token.value)))
        invalidExpression();
      return token;
    }
    function primary(depth) {
      if (depth > 64) invalidExpression();
      if (next() === '(') {
        position++;
        const value = disjunction(depth + 1);
        if (next() !== ')') invalidExpression();
        position++;
        return value;
      }
      let atom = identifier().value;
      if (next() === 'WITH') {
        const operator = tokens[position++];
        if (
          !/[ \t]/u.test(expression[operator.start - 1] ?? '') ||
          !/[ \t]/u.test(expression[operator.end] ?? '')
        )
          invalidExpression();
        const exception = identifier().value;
        if (
          exception.includes(':') ||
          exception.startsWith('LicenseRef-') ||
          exception.endsWith('+')
        )
          invalidExpression();
        atom += ` WITH ${exception}`;
      }
      const rank = allowed.findIndex((list) => list.has(canonical(atom)));
      return rank < 0 ? 3 : rank;
    }
    function conjunction(depth) {
      let value = primary(depth);
      while (next() === 'AND') {
        position++;
        value = Math.max(value, primary(depth));
      }
      return value;
    }
    function disjunction(depth) {
      let value = conjunction(depth);
      while (next() === 'OR') {
        position++;
        value = Math.min(value, conjunction(depth));
      }
      return value;
    }
    const result = disjunction(0);
    if (position !== tokens.length) invalidExpression();
    return dispositions[result];
  } catch (error) {
    if (error instanceof SyntaxError) return 'DENY';
    throw error;
  }
}

export function classifyInventory(inventory, policy) {
  if (!inventory || typeof inventory !== 'object' || Array.isArray(inventory))
    throw new TypeError('Invalid license inventory');
  for (const packages of Object.values(inventory)) {
    if (
      !Array.isArray(packages) ||
      packages.length === 0 ||
      packages.some(
        (entry) =>
          !entry ||
          typeof entry.name !== 'string' ||
          !entry.name.trim() ||
          !Array.isArray(entry.versions) ||
          entry.versions.length === 0 ||
          entry.versions.some((version) => typeof version !== 'string' || !version.trim()),
      )
    )
      throw new TypeError('Invalid license inventory entry');
  }
  const findings = Object.entries(inventory)
    .map(([expression, packages]) => ({
      expression,
      packageCount: packages.length,
      disposition: classifyLicense(expression, policy),
      components: packages.flatMap((entry) =>
        entry.versions.map((version) => `${entry.name}@${version}`),
      ),
    }))
    .sort((left, right) => left.expression.localeCompare(right.expression));
  return {
    findings,
    localTechnicalStatus:
      findings.length === 0 || findings.some(({ disposition }) => disposition === 'DENY')
        ? 'FAIL'
        : 'PASS',
    releaseQualification:
      findings.length > 0 && findings.every(({ disposition }) => disposition === 'ALLOW')
        ? 'LOCALLY_LICENSE_ELIGIBLE'
        : 'NOT_PROVEN_OPEN',
  };
}
