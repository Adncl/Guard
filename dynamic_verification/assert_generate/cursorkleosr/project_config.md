# Project Configuration (LTM)

*This file contains the stable, long-term context for the project.*
*It should be updated infrequently, primarily when core goals, tech, or patterns change.*

---

## Core Goal

Read the contents of each text file in cursorkleosr/task/ step by step and perform different tasks according to their content descriptions. During this time, follow the task description to automate the generation and insertion of custom functions and assertion statements.

---

## Tech Stack

*(List the primary technologies, frameworks, and languages used. E.g.,)*
*   **C/C++ languages**

---

## Critical Patterns & Conventions

*(Document any non-standard but crucial design patterns, architectural decisions, or coding conventions specific to this project. E.g.,)*
*   **Custom functions (implementing missing code logic):** If you need to implement custom functions, follow the style of existing related code and the way functions and variables are called; guessing and fabrication are prohibited.

---

## Key Constraints

*(List any major limitations or non-negotiable requirements. E.g.,)*
1. **Support C/C++ Language**: The solution must exclusively use C or C++ programming languages to align with the current project requirements.  

2. **Avoid Third-Party Dependencies**: Do not rely on any third-party library files. If a standard header file is required, verify its existence before including it at the beginning of the file.  

3. **Prioritize Original Packet Values in ASSERT Statements**: When tracking multiple variables in an `ASSERT` statement, prioritize the value closest to the original packet rather than processed values.  

4. **Ensure Unique Custom Function Naming**: Combine the custom function name with the corresponding file name in `cursorkleosr/task/` to prevent duplication.  

5. **Declare Custom Functions Early**: If introducing a custom function, explicitly declare it at the beginning of the file.  

6. **Place Assertions Near Offending Code**: Insert assertion statements as close as possible to the problematic code location, ensuring the tracked variable has been initialized or assigned a value.
---

## Tokenization Settings

*   **Estimation Method:** Character-based
*   **Characters Per Token (Estimate):** 4
