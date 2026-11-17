import assert from "node:assert/strict";
import test from "node:test";
import { safeReturnTo } from "../src/returnTo.ts";

test("a callback always produces a path that history can resolve on the app origin", () => {
  const origin = "https://app.example.test";
  assert.equal(safeReturnTo("/account/../profile?tab=roles#details", origin), "/profile?tab=roles#details");
  for (const value of [null, "//another.example", "/local/..//section", "/\t/[invalid", "/a\\b"]) {
    assert.equal(safeReturnTo(value, origin), "/");
  }
});
