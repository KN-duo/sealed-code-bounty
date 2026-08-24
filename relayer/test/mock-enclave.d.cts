declare module "mock-enclave.cjs" {
  export interface MockEnclaveHandle {
    url: string;
    pubkeyB58: string;
    close(): Promise<void>;
  }
  export function startMockEnclave(opts?: { tamper?: boolean }): Promise<MockEnclaveHandle>;
}
