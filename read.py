import os
import sys
from pathlib import Path

# ===== Cấu hình =====
OUTPUT_FILE = "project_docs.md"

IGNORE_DIRS = {
    ".git", ".idea", ".vscode", "__pycache__",
    "venv", ".venv", "env", "node_modules",
    "dist", "build",
}

IGNORE_FILES = {OUTPUT_FILE, ".DS_Store"}

TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx",
    ".java", ".cpp", ".c", ".h",
    ".cs", ".go", ".rs",
    ".html", ".css", ".scss",
    ".json", ".yaml", ".yml",
    ".xml", ".toml", ".ini",
    ".md", ".txt",
    ".sql", ".sh", ".bat",
    ".dockerfile", ".env",
}
# ====================


def is_text_file(path: Path):
    if path.suffix.lower() in TEXT_EXTENSIONS:
        return True
    try:
        with open(path, "r", encoding="utf-8") as f:
            f.read(1024)
        return True
    except Exception:
        return False


def build_tree(root):
    lines = [Path(root).resolve().name]

    def walk(directory, prefix=""):
        try:
            entries = sorted(
                e for e in os.listdir(directory)
                if e not in IGNORE_DIRS and e not in IGNORE_FILES
            )
        except PermissionError:
            return

        for i, name in enumerate(entries):
            path = os.path.join(directory, name)
            connector = "└── " if i == len(entries) - 1 else "├── "
            lines.append(prefix + connector + name)
            if os.path.isdir(path):
                extension = "    " if i == len(entries) - 1 else "│   "
                walk(path, prefix + extension)

    walk(root)
    return "\n".join(lines)


def main():
    project_dir = sys.argv[1] if len(sys.argv) > 1 else "."

    with open(OUTPUT_FILE, "w", encoding="utf-8") as out:
        out.write("# Project Documentation\n\n")
        out.write("## Directory Tree\n\n```text\n")
        out.write(build_tree(project_dir))
        out.write("\n```\n\n# Files\n\n")

        # os.walk đi qua TẤT CẢ các folder con lồng nhau (đệ quy tự động)
        for root, dirs, files in os.walk(project_dir):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            files.sort()

            for file in files:
                if file in IGNORE_FILES:
                    continue

                path = Path(root) / file
                if not is_text_file(path):
                    continue

                relative = path.relative_to(project_dir)
                out.write("---\n\n")
                out.write(f"## {relative}\n\n")

                lang = path.suffix.lstrip(".")
                out.write(f"```{lang}\n")

                try:
                    with open(path, "r", encoding="utf-8") as f:
                        out.write(f.read())
                except UnicodeDecodeError:
                    try:
                        with open(path, "r", encoding="latin-1") as f:
                            out.write(f.read())
                    except Exception:
                        out.write("[Không thể đọc file]")
                except Exception as e:
                    out.write(f"[Lỗi: {e}]")

                out.write("\n```\n\n")

    print(f"Đã tạo: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()