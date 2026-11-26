"""Check policy discovery structure, not whether an AI follows instructions."""

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOPICS = (
    "architecture",
    "backend",
    "database",
    "frontend",
    "operations",
    "review",
    "security",
    "workflow",
)


class AgentInstructionsTests(unittest.TestCase):
    def test_shared_docs_are_separate_from_skill_discovery(self):
        self.assertTrue((ROOT / ".ai/README.md").is_file())
        self.assertFalse((ROOT / "agents").exists())
        self.assertTrue((ROOT / ".agents/skills/bomhort-review/SKILL.md").is_file())

    def test_entry_points_route_to_guardrail_and_skill_inventory(self):
        for name in (
            "AGENTS.md",
            "CLAUDE.md",
            ".github/copilot-instructions.md",
            ".agents/skills/bomhort-review/SKILL.md",
            ".claude/skills/bomhort-review/SKILL.md",
        ):
            with self.subTest(file=name):
                self.assertIn(".ai/README.md", (ROOT / name).read_text())
        inventory = (ROOT / ".ai/README.md").read_text()
        for folder in (".agents", ".claude"):
            self.assertIn(f"../{folder}/skills/bomhort-review/SKILL.md", inventory)

    def test_root_routes_to_every_topic_and_stays_small(self):
        root = ROOT / "AGENTS.md"
        text = root.read_text()
        self.assertLessEqual(root.stat().st_size, 8 * 1024)
        self.assertIn("## Code Review Rules", text)
        for topic in TOPICS:
            with self.subTest(topic=topic):
                self.assertIn(f".ai/{topic}.md", text)
                self.assertTrue((ROOT / ".ai" / f"{topic}.md").is_file())

    def test_local_markdown_links_resolve(self):
        files = [ROOT / "AGENTS.md", *sorted((ROOT / ".ai").glob("*.md"))]
        for path in files:
            for target in re.findall(r"\[[^\]]*\]\(([^)]+)\)", path.read_text()):
                if "://" in target or target.startswith("#"):
                    continue
                with self.subTest(file=path.name, target=target):
                    self.assertTrue((path.parent / target.split("#")[0]).exists())

    def test_claude_imports_root_without_eager_domain_imports(self):
        text = (ROOT / "CLAUDE.md").read_text()
        imports = re.findall(r"^@(.+)$", text, re.MULTILINE)
        self.assertEqual(imports, ["AGENTS.md"])

    def test_copilot_adapters_have_routing_and_small_budgets(self):
        files = [
            ROOT / ".github/copilot-instructions.md",
            *sorted((ROOT / ".github/instructions").glob("*.instructions.md")),
        ]
        self.assertGreater(len(files), 1)
        for path in files:
            text = path.read_text()
            with self.subTest(file=path.name):
                self.assertLessEqual(len(text), 4000)
                self.assertIn("AGENTS.md", text)
                self.assertIn(".ai/review.md", text)
                if path.name.endswith(".instructions.md"):
                    self.assertTrue(text.startswith("---\napplyTo: "))
                    self.assertIn("\n---\n", text[4:])
        review = (ROOT / ".github/instructions/review.instructions.md").read_text()
        self.assertIn('excludeAgent: "cloud-agent"', review)

    def test_review_skills_route_to_one_shared_procedure(self):
        for folder in (".agents", ".claude"):
            path = ROOT / folder / "skills/bomhort-review/SKILL.md"
            text = path.read_text()
            with self.subTest(folder=folder):
                self.assertTrue(text.startswith("---\n"))
                self.assertIn("\nname: bomhort-review\n", text)
                self.assertRegex(text, r"\ndescription: .+\n")
                self.assertIn("AGENTS.md", text)
                self.assertIn(".ai/review.md", text)
                self.assertLessEqual(len(text), 2000)


if __name__ == "__main__":
    unittest.main()
