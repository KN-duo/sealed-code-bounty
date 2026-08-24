/** Error with a process exit code attached — index.ts maps these 1:1. */
export class PackError extends Error {
  constructor(
    public readonly exitCode: number,
    message: string
  ) {
    super(message);
    this.name = "PackError";
  }
}

export const EXIT_USAGE = 2;
export const EXIT_DOCKER_UNAVAILABLE = 3;
export const EXIT_FLAG_INVALID = 4;
export const EXIT_UPLOAD_NOT_IMPLEMENTED = 5;
export const EXIT_BUILD_FAILED = 6;
export const EXIT_SAVE_FAILED = 7;
