let isListening = false;

export class TerminalUI {
  private currentInput: string = "";
  private prompt: string = "> ";

  constructor(private onLineEntered: (line: string) => void) {
    process.stdin.setRawMode(true);
    process.stdin.resume();
    this.drawPrompt();
    this.listen();
  }

  // Use this instead of console.log
  public log(message: string) {
    // \r moves cursor to start, \x1b[K clears the line
    process.stdout.write(`\r\x1b[K${message}\n`);
    this.drawPrompt();
  }

  private drawPrompt() {
    process.stdout.write(`\r\x1b[K${this.prompt}${this.currentInput}`);
  }

  private async listen() {
    if (isListening) return; // Prevent multiple loops
    isListening = true;

    // Using 'console' helper is often safer in Bun for line-based input
    // but since we want Raw Mode, we use the process.stdin directly
    const reader = process.stdin;

    reader.on("data", (chunk) => {
      const char = chunk.toString();

      if (char === "\r" || char === "\n") {
        const line = this.currentInput.trim();
        this.currentInput = "";
        process.stdout.write("\n");
        if (line) this.onLineEntered(line);
        this.drawPrompt();
      } else if (char === "\x7f") {
        this.currentInput = this.currentInput.slice(0, -1);
        this.drawPrompt();
      } else if (char === "\u0003") {
        process.exit();
      } else {
        this.currentInput += char;
        this.drawPrompt();
      }
    });
  }
}
