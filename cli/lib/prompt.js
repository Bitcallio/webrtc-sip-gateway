"use strict";

const readline = require("readline");
const { stdin: input, stdout: output } = require("process");

class Prompter {
  constructor() {
    this.rl = readline.createInterface({ input, output });
  }

  close() {
    this.rl.close();
  }

  async askText(label, defaultValue = "", { required = false } = {}) {
    for (;;) {
      const suffix = defaultValue !== "" ? ` [${defaultValue}]` : "";
      const answer = (await this._question(`${label}${suffix}: `)).trim();
      const value = answer || defaultValue;

      if (required && !value) {
        console.log("Value is required.");
        continue;
      }

      return value;
    }
  }

  async askChoice(label, options, defaultIndex = 0) {
    console.log(label);
    options.forEach((option, index) => {
      console.log(`  ${index + 1}. ${option}`);
    });

    for (;;) {
      const answer = (await this._question(`Choose [${defaultIndex + 1}]: `)).trim();
      const selected = answer ? Number.parseInt(answer, 10) : defaultIndex + 1;
      if (!Number.isNaN(selected) && selected >= 1 && selected <= options.length) {
        return options[selected - 1];
      }
      console.log("Invalid selection.");
    }
  }

  async askYesNo(label, defaultYes = true) {
    const hint = defaultYes ? "[Y/n]" : "[y/N]";
    for (;;) {
      const answer = (await this._question(`${label} ${hint}: `)).trim().toLowerCase();
      if (!answer) {
        return defaultYes;
      }
      if (answer === "y" || answer === "yes") {
        return true;
      }
      if (answer === "n" || answer === "no") {
        return false;
      }
      console.log("Please answer yes or no.");
    }
  }

  _question(message) {
    return new Promise((resolve) => {
      this.rl.question(message, (answer) => resolve(answer));
    });
  }
}

module.exports = {
  Prompter,
};
