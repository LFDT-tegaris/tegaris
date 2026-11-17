import assert from 'node:assert/strict';

// Recovery reads may wait only for a classified transport/dependency restart.
// Business denials and unclassified failures remain terminal.
export async function publicReadResponse(response, recovering = false) {
  if (recovering && response.status === 503) {
    const mediaType = response.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase();
    if (mediaType === 'application/json' || mediaType === 'application/problem+json') {
      const problem = await response.json();
      assert.equal(problem.code, 'PC-INTEGRATION-5001');
      assert.equal(problem.retryable, true);
      if (mediaType === 'application/problem+json') {
        assert.equal(problem.status, 503);
        assert.equal(problem.truthState, 'UNAVAILABLE');
      }
    } else {
      assert.equal(
        (await response.text()).trim(),
        'upstream connect error or disconnect/reset before headers. reset reason: remote connection failure',
      );
    }
    return null;
  }
  assert.equal(response.status, 200);
  return response.json();
}
