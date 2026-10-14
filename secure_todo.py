#!/usr/bin/env python3
"""
Secure To-Do List Application
Demonstrates secure coding practices including strict input validation, 
fail-secure error handling, defense in depth, and principle of least privilege/immutability.
"""

import sys
import html
import logging

# Configure secure logging (Defense in Depth / Audit Trail)
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    stream=sys.stderr
)

class SecureTodoList:
    def __init__(self):
        # Principle: Least Privilege / Secure State Management
        # Internal list is private (by convention) to prevent direct external mutation.
        self._tasks = []
        self._max_tasks = 100  # Resource exhaustion defense (Denial of Service mitigation)

    def add_task(self, raw_input_str: str) -> bool:
        """
        Adds a task after rigorous input validation and sanitization.
        Demonstrates: 
          1. Input Validation (Type & Length checks)
          2. Sanitization (HTML escaping to prevent injection if rendered in a UI later)
        """
        # 1. Type validation
        if not isinstance(raw_input_str, str):
            logging.warning("Invalid type passed to add_task: %s", type(raw_input_str))
            raise TypeError("Task input must be a string.")

        # 2. Length validation (Prevent buffer/memory exhaustion)
        cleaned_input = raw_input_str.strip()
        if not cleaned_input:
            raise ValueError("Task description cannot be empty or whitespace only.")
        
        if len(cleaned_input) > 256:
            raise ValueError("Task description exceeds maximum allowed length of 256 characters.")

        # 3. Resource limit check (Denial of Service defense)
        if len(self._tasks) >= self._max_tasks:
            raise RuntimeError("Task limit reached. Cannot add more tasks securely.")

        # 4. Sanitization: Escape special characters to prevent stored XSS or injection downstream
        sanitized_task = html.escape(cleaned_input)

        self._tasks.append({"task": sanitized_task, "completed": False})
        logging.info("Task added successfully (Length: %d)", len(sanitized_task))
        return True

    def complete_task(self, index_str: str) -> bool:
        """
        Marks a task as complete with strict boundary and type checking.
        """
        try:
            # Strict integer parsing and bounds checking
            task_idx = int(index_str) - 1
            if task_idx < 0 or task_idx >= len(self._tasks):
                raise IndexError("Task index is out of valid range.")
            
            self._tasks[task_idx]["completed"] = True
            logging.info("Task %d marked as completed.", task_idx + 1)
            return True
        except ValueError:
            # Fail-Secure: Catch parsing errors explicitly and raise clean validation error
            raise ValueError("Invalid index format. Please provide a numeric value.")

    def get_tasks(self) -> list:
        """
        Returns a shallow copy of tasks to enforce encapsulation 
        and prevent unauthorized external mutation of internal state.
        """
        return [dict(task) for task in self._tasks]


# ==========================================
# Application Controller & Fail-Secure Loop
# ==========================================
def main():
    todo_app = SecureTodoList()
    print("=== Secure To-Do List Application ===")

    while True:
        print("\nMenu:")
        print("1. View Tasks")
        print("2. Add Task")
        print("3. Complete Task")
        print("4. Exit")

        try:
            choice = input("Select an option (1-4): ").strip()
            
            if choice == "1":
                tasks = todo_app.get_tasks()
                if not tasks:
                    print("\n[Your To-Do list is currently empty]")
                else:
                    print("\nYour Tasks:")
                    for idx, t in enumerate(tasks, 1):
                        status = "✓" if t["completed"] else " "
                        print(f"[{status}] {idx}. {t['task']}")

            elif choice == "2":
                task_desc = input("Enter task description: ")
                # Principle: Proper input validation & handling
                todo_app.add_task(task_desc)
                print("-> Task successfully added!")

            elif choice == "3":
                task_num = input("Enter task number to mark complete: ")
                todo_app.complete_task(task_num)
                print("-> Task marked as complete!")

            elif choice == "4":
                print("Exiting securely. Goodbye!")
                sys.exit(0)

            else:
                print("[Error] Invalid selection. Please choose an option between 1 and 4.")

        except (ValueError, TypeError, RuntimeError, IndexError) as e:
            # Principle: Fail-Secure Error Handling
            # The program catches specific expected validation/runtime errors,
            # prevents crash/stack-trace leakage to the end user, and logs the event securely.
            print(f"\n[Security/Validation Error]: {e}")
            logging.warning("Handled operational exception: %s", e)

        except Exception as e:
            # Fail-secure catch-all for completely unexpected faults
            logging.critical("Unexpected critical error occurred: %s", e)
            print("\n[Critical Error] An unexpected system error occurred. Operation aborted safely.")


if __name__ == "__main__":
    main()