# Code Review Checklist

Status as of 2026-03-30, based on a repo-wide spot review and the latest SonarCloud cleanup pass.

## Coding Style

- [x] 1. The names of variables, functions, and classes are understandable and descriptive.
- [x] 2. A standard or team-defined naming convention has been used.
- [x] 3. The code been properly organized into different files and folders.

## Comments

- [ ] 4. All the important modules (functions, classes, etc.) have header comments.
- [ ] 5. The comments are consistent in format, length, and level of detail.
- [x] 6. There is no code that has been commented out, which should otherwise be removed.

## Error Handling

- [ ] 7. All exceptions/errors are handled properly according to the language/framework conventions.
- [x] 8. The error messages are understandable.
- [ ] 9. The code takes care of edge/boundary cases (null, 0, negative, min, max etc.).
- [x] 10. All files/connections are opened before use and are closed after use.
- [ ] 11. Specific exceptions are handled. (Note: handle specific exceptions, not a general block for handling all kinds of exceptions.)

## Source Code Logic

- [x] 12. All the loops terminate.
- [ ] 13. There are no statements that can be taken out of a loop.
- [ ] 14. The code is modular, i.e., there are no complex functions (or classes) that should better be split into multiple functions (or classes).
- [x] 15. All the variables are properly initialized.
- [x] 16. For each expression with more than one operator, the order of evaluation is correct.
- [ ] 17. There are no hardcoded strings, credentials or configuration information.
- [x] 18. A logging library has been used to log important information.

## Notes

- Items 7, 11, 14, and 17 remain open because the repo still contains several broad `except Exception` handlers, a few large controller/service functions, and hardcoded runtime defaults such as host values and API-key examples in code/docs.
- Item 4 remains open because many important backend modules have headers, but this is not consistent across the entire codebase.
- Item 5 remains open because the repo mixes module headers, JSX section comments, JSDoc blocks, TODO-style comments, and sparse modules with no commentary.
- Item 6 is marked complete after removing commented-out UI code from the dashboard and deleting the unused `LogsTable.tsx.backup` file.
