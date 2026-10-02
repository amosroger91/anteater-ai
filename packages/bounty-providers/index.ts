import { fixture } from '../../fixtures/program.js';
export interface BountyProvider { discover(): Promise<readonly typeof fixture[]> }
// No network discovery in the initial milestone. Discovery data never implies authorization.
export class FixtureProvider implements BountyProvider {
  async discover() { return [structuredClone(fixture)]; }
}
