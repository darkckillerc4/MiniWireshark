# Using MiniWireshark with the keyboard only

Everything in MiniWireshark can be reached without a mouse. This page is the short walkthrough; the full key table is in the [User guide](USER-GUIDE.md#keyboard-shortcuts).

## Start here

| Keys | What it does |
|---|---|
| `Ctrl+K` | Opens the "go to anything" box. Type a word to find a tab, a setting or an action; `Enter` runs it. |
| `Shift+F1` | Lists every key, so you do not have to remember them. |
| `F6` / `Shift+F6` | Moves to the next or previous part of the window: search, tabs, filter, table, inspector and status. |
| `F7` | Goes straight to the table. |

## What the `Ctrl+K` box understands

- A plain word finds tabs, settings pages and actions. It ignores accents and ranks whole words first.
- `:123` jumps to packet 123.
- `ip:…` or `/…` sets a filter. `>` lists commands, `@` devices and websites, `?` help. `Tab` changes the group of results.
- What you used lately is remembered on this computer only, and it never keeps device or website names.

## Moving around

1. From the search box, `Tab` reaches the first control of a tab in about six presses: one stop for the tabs, one for the sub-views and one for the toolbar. Inside each stop the arrow keys move along, and `Left` / `Right` / `Home` / `End` work on the tabs and sub-views.
2. `Ctrl+Tab` and `Ctrl+Shift+Tab` change tab. `Ctrl+1` … `Ctrl+4` change tab group.
3. In a table, `Enter` opens the selected row, `Home` / `End` jump to the first or last row, and `Ctrl+A` selects all rows.
4. The `Menu` key or `Shift+F10` opens the selected row's menu. `Alt+Down` opens the column menu. To sort, press `Shift+Left` or `Shift+Right` to pick a column, then `Shift+Enter`.
5. The Inspector, Help and detail text can be focused and scrolled with the keys. `Ctrl+Shift+arrows` move a divider.

## Changing keys

Every shortcut can be changed in **Settings → Keyboard Shortcuts**. Settings refuses a key that Tk's text boxes or the window already use, so a change cannot break typing.

## How this is checked, and what is not

The GUI test (`python miniwireshark.py --gui-test`) presses these keys in a real window and checks where the focus lands, including a step that follows the `Tab` order across the Dashboard cards. Continuous integration runs it on Linux and Windows; see [Trust](TRUST.md). The focus ring on drop-down lists, number boxes and Dashboard cards is checked too.

What it does not prove: it has not been tested with a screen reader. If something in the keyboard path is missing or out of order, [open an issue](https://github.com/darkckillerc4/MiniWireshark/issues).
