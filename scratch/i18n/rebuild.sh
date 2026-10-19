set -e
cd /home/claude/mw
git checkout -q miniwireshark.py
python3 scratch/i18n/apply.py scratch/i18n/part*.tsv
python3 scratch/i18n/apply2.py
python3 -c "import ast;ast.parse(open('miniwireshark.py').read())"
