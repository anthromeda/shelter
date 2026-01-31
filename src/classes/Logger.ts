import chalk from "chalk";

export default class Logger {
  constructor(private enabled: boolean = false) {}

  log(...args: any[]) {
    if (this.enabled) {
      console.log(chalk.blue("LOG:"), ...args);
    }
  }

  error(...args: any[]) {
    if (this.enabled) {
      console.error(chalk.red("ERROR:"), ...args);
    }
  }

  warn(...args: any[]) {
    if (this.enabled) {
      console.warn(chalk.yellow("WARN:"), ...args);
    }
  }
}
