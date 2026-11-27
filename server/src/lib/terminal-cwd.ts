const OSC7_REGEX =
  /\x1b\]7;file:\/\/[^/\s]*(\/[^\x07\x1b]*)(?:\x07|\x1b\\)/g;

const SHELL_CWD_SETUP_ECHO =
  /[^\n]*export PROMPT_COMMAND=[^\n]*(\r?\n|$)/g;

export function extractAndStripOsc7(
  data: string,
): { output: string; cwd: string | null } {
  let cwd: string | null = null;

  const output = data.replace(OSC7_REGEX, (_match, path: string) => {
    if (!path) return "";
    try {
      cwd = decodeURIComponent(path);
    } catch {
      cwd = path;
    }
    return "";
  });

  return { output, cwd };
}

export function stripShellSetupEcho(text: string): string {
  return text.replace(SHELL_CWD_SETUP_ECHO, "");
}

/** Sent once after the shell is ready; echo is stripped in forwardShellOutput. */
export const SHELL_CWD_SETUP =
  "export PROMPT_COMMAND='printf \"\\033]7;file://${HOSTNAME}${PWD}\\033\\\\\"'\n";
