# The companion application

This is the desktop application in `apps/companion`. It shows the attention inbox, the sessions on
each host, the semantic conversation and the raw terminal, and it reaches a host through the same
native client library the command line uses.

## What it is made of

| Part | Where | What it owns |
| --- | --- | --- |
| The interface | `apps/companion/src` | Every screen, in TypeScript and React |
| The native backend | `apps/companion/src-tauri` | The connection, the named commands, the boundary |
| The shared client | `crates/kr-client` | Sessions, cursors, projection, drafts, uploads |

The interface reads protocol values and writes protocol parameters. It holds no connection, no
socket and no path. That is what lets the same screens run on the desktop, where the commands reach
the native backend, and under test, where they reach a host that answers without a machine behind
it.

```text
  the window                      the backend                    the host
  ────────────────────   invoke   ──────────────────   kr-client  ────────
  session_list        ──────────▶ Method::SessionList ──────────▶ session.list
  agent_prompt_submit ──────────▶ Method::AgentPromptSubmit ────▶ the session's own worker
  open_external       ──────────▶ the scheme policy, then the platform opener
```

The agent's methods are each session's own. Native code reaches a session's worker over that
session's own link, the one the terminal view's input already takes, and checks that the process at
the other end is the session's worker before it sends anything; the worker checks this device's
rights itself. A read of the agent names the session and the instance, and a mutation also names
the binding revision the person saw, so an action prepared against a conversation that has since
moved is refused rather than applied to the new one. The attention inbox, review and change sets,
sharing and packages are the daemon's, through the host's local door, and a session's retained
output is read from its worker while it runs and from the daemon's archive once it has ended. An
operation whose parameters or result the protocol does not publish has no command, and the page
refuses it with `UNSUPPORTED_SCHEMA`.

Questions in a session are owned by that session’s worker. When the host is on the same computer, this page can simply read questions and answer them using the same link as the agent uses to call it. When the host is on another computer that this one is paired with, the host’s daemon will pass questions from its worker to this one, using the rights it was given when the pairing was established. Each question shows the program the worker verified, with the full path of its executable and its process. Beside that it shows the name the program has given itself, which is not verified. An answer commits on a completed press and names the revision the person saw. If the question changed while the person was typing, the first press says so and a second press sends the answer. The worker resolves a question once, for whoever answers first. If another device answers first, or the question expires or is withdrawn, the page says how it ended and keeps what the person had chosen until they dismiss it, whether or not they pressed Send.

If the host does not confirm that it has taken an answer, either because the connection to it has ended or because the worker has said nothing for twenty seconds, a copy of the answer is kept on this device, in a directory for each environment, and the page says so. Only the person sends a kept answer, and only to the host it was given to. When that host is reachable again, its questions are read and the page says whether each kept answer can still be sent. One whose question ended or changed stays kept, with what became of the question, until the person discards it. Each kept answer names its session and, when the host can say, its question. All operations that change the kept answers take a lock shared among all windows of this application, so a second window cannot lose one or send one twice.

The command line and the application keep the answers they could not deliver in separate stores, and the two share nothing. (The phone has no command line so only has the application's store of answers.) The host will only accept the first answer it receives to any given question. If the host receives an answer to a question from one store of answers, it will not accept an answer from the other store of answers.

A failure the page shows says the host's own words and, where its code maps to something the person
can do, that action after them: pair the device again, sign in, update, wait, refresh, check
whether it went through, or change a setting. The client library says a host's refusal as its code,
a colon and the host's words, and the page leaves the code out. A failure whose code asks nothing of
the person says the host's words alone. Native code names the action by its key, and the page's
words for each key are the client library's own. A refusal the application makes itself, for a
cause it knows (a size limit, a dropped folder, input the program cannot read, a call or a
verification this device cannot make), names no action: its words say what is wrong, and no update,
wait or setting would change it.

Native code tells the page about changes through listeners: the connection's state, the host's
events, where the account stands, pairing, owner confirmations and dropped files. The shell
registers a listener asynchronously and drops whatever it publishes before then. Each listener
therefore resolves only once it is registered, and a screen reads the state it follows only after
that, so no change can fall between the two. Nor does a screen show an answer once its listeners
have stopped, or when they could not be registered. A change that arrives before the read's answer
is at least as new as that answer, and the screen keeps it. A screen that reads again, on a change,
a retry, a refresh or an action, shows only its newest read's answer, and the raw terminal view shows
nothing it read for a session it has left. The host announces no new entry in an agent's history,
no change to the attention inbox and no new request an agent is waiting on, so a screen that shows
one reads it again while the page is shown: on a cadence, and at once when the page is shown again
or the host is heard to be back. It has one read on its way at a time, and a read asked for
meanwhile, as after an action, follows it. The inbox and review state are read page by page, and
a list the bound cut short says the host holds more. The conversation reads each agent's history
from the entry after the last one it holds, and counts what the host withheld from this device once
however often it reads; an entry withheld after a read passed its place can go uncounted, so the
count is a lower bound and says "at least". An agent's history goes with it when it ends, so the conversation says when
one it was reading ended before its last entries were read. What a package shows arrives on the
event stream, and a node already held is replaced only by a newer revision of it.

A session has three views: the conversation, the raw terminal and its output. The output view reads
what the session wrote, as the host keeps it, with `history.page`: from the live end, a page at a
time with a cursor and a byte bound, towards older output as the reader scrolls up and newer output
as they scroll down. It holds a bounded run of pages and lets pages go from the far end, and the page
the reader is looking at stays where it is as pages come and go. It shows the text the session
printed, decoded across page boundaries, and leaves out what a terminal would act on: colours,
titles, cursor moves and clipboard writes. Where the host no longer keeps output it says so, and
why. Each view keeps its own place across a change of view: the conversation and the output return
the reader to the node or page they were reading, or to the live end if they were following it.

A session exports two files, each where the platform's save dialog puts it. The semantic archive
holds each entry of every live agent's history as the session's worker gives it, with its time, at
the session's own size, and declares the entries this device's filter withheld, the ones cut short
and the ranges the host no longer kept. The recording holds each screen the raw terminal view drew
while it was open, when it drew it and at the size it drew it, and plays back at the last size. A
screen is written as positions and colours, never as the bytes the session printed. The recording
keeps at most 2,000 screens and 8 MiB of drawing, counted in bytes of UTF-8, and declares the
earlier screens it let go, a screen larger than all of that, and the screens drawn at another size.
Every colour is drawn as the view resolved it through the session's palette; the cursor's shape and
colour, and underline styles other than single and double, are declared rather than drawn, because
a player draws those in its own. Before the terminal view has drawn, there is no recording to
export.

A session is created from the session list, in a directory the person names, with its shell chosen
first. A managed shell is the host's qualified package: Ctrl-D at an empty prompt detaches the view,
and the host reads the shell's editor, so it knows when the prompt is empty. A stock shell is the
system's own, for compatibility: Ctrl-D does what the shell does and can close the session, and the
editor is not read. Where the host describes a session's launch surface, a managed shell's launch
buttons start an agent at the prompt, and a stock shell's show the command to type and start
nothing. Attaching, detaching, closing, file transfer, agents and the terminal work in both. The
creation sheet shows the two side by side before anything exists, and a stock shell is labelled in
the session list, the session's header and settings, and the phone's list. A managed shell the host
cannot qualify is refused with the host's reason; a stock shell is created only when the person
chooses one. The sheet starts on the shell the host says it creates when nothing names one, which is
the mode in the host's configuration and otherwise the managed shell, and it says which of the two
that is; a choice made in the sheet is for that session only. The creation sends none of this
device's environment: the host decides what the session starts with.

Each row in the session list will display the name that has been provided by the host. Until the host provides a name, the session directory name will be displayed instead. A title the host made from the session's metadata will be shown with no label. If the session has been pinned with a name, the name will be displayed next to “Pinned”. If the local model has written a title for the session, it will be displayed next to “Generated”, with the line the model wrote about what the session is doing below it. If that line is out of date, or there is a newer line waiting, a line will be included saying so. For each session listing displayed on screen, and a buffer above and below, the host will be asked for this information, and again every thirty seconds while the list is shown. If the user is searching, all session listings will be asked, so that the search can be run against the titles. If a read fails, the row stays as it was.

Each row also names the application in the foreground of the session, in a column of the desktop's list and in the detail line of the phone's. The name is the one the worker reports. A session at a shell prompt says "Shell", a session whose program the worker has no name for says nothing, and a closed session says "None" in the desktop's column, because what ran in it is not known any more.

Setup offers session descriptions from the host's own answer. Initially, the card will display the size of the download, as well as the source of the download. It will also say that no account is needed. Once the user presses the download button, the progress of the download will be shown in the card. If it fails, the reason for failure will be shown. The card also contains a button to cancel the download, a switch to turn session descriptions on or off, and a switch to allow them on battery power. All of these will require the host to perform the action, and the card will display the result given by the host. If the host has paused inference, for example because it is on battery power, the card says why. When the host refuses a change, the card displays the refusal in the host's words.

A draft keeps the conversation it was written for: the agent's instance and the binding revision the
person wrote to. If the agent moves to another conversation while the draft is on screen, the draft
is conflicted and nothing sends it on; the person chooses whether it goes to the new one. A draft
written before the agent was read keeps the first conversation it learns.

A file dropped onto the window or pasted into the composer, when files are offered, is on the draft from that moment. The application sends it to the host running on this computer through the transfer service, and it stays on the draft whether the sending succeeds or fails. When a file is dropped, the platform gives its path to native code directly, so the page never holds its bytes. When a file is pasted, it goes to the page, which hands its bytes to native code if the file is at most 64 MiB, and native code sends it by the same upload. When the host has made a small picture of an image, that picture is shown next to the file's name.

Files are offered only while the application is in contact with the host on this computer and holds the rights to upload a file and to send a prompt. A host that this device is paired with takes no file from it, so over one no file is offered. A phone reaches a host only by pairing, so the pickers of the phone layout are disabled, and while a host is connected the reason is displayed next to them.

Once a file is uploaded, the application binds it on the host as a manual terminal workflow and shows the path the host gives, with the time that path stops holding. The path can be selected and copied. It is not quoted for any shell, so the person quotes it for their own shell and gives it to the agent in the terminal. The application inserts nothing into an agent's composer. If the host refuses the path, or does not say whether it gave one, the file stays on the draft, the screen says so in words, and a button asks again.

A prompt sent from a draft carries its text only, so a draft that holds a file is not sent until the person removes the file.

Nothing that needs a right is offered before the connection has said what it
may do. In a session, when the launch surface was read at an older prompt generation than the view
has heard since, its buttons start disabled.

On the phone, a host that stops answering while the session is in front detaches the session's draft from the conversation it was written for, as a suspension does: the text, its revision and its files are untouched, the composer says the draft is kept here and is not in contact with the host, and Send is off. When the host answers again and the conversation is unchanged, the draft is bound to it again; a draft written for a conversation that has moved on is the person's to settle. The placeholder in the field is the same in the conversation and the terminal view, and Send sends the text to the agent in both.

Drafts are kept on this device as they are typed. The application writes each change to a store of its own that outlives the window, so a draft is still in its composer when the application is closed and opened again, when a tab is closed and opened again, and while the host is out of reach. The composer waits for the store to be read, so nothing typed can replace what was kept. If the device cannot open the store, drafts are kept in the window only, the person is told, and a button tries the store again. A draft is never replaced because another window of the application changed it first: the stored draft stays as that window left it, this window’s text is kept beside it as a separate draft, and a message says so. If a draft is removed from the store by another window, the next time the text is modified it will be stored as a new draft. A prompt sent from a draft takes the stored draft with it, as it stood when the person pressed Send, and what is typed after that is a draft of its own. The stored draft is removed when the host has taken the prompt. If the host refuses the prompt, or nobody knows what became of it, the text goes back to the composer when the composer is empty. When the person has written something new since, the text of the prompt stays a stored draft of its own and is listed under Kept drafts, so neither text replaces the other. Files on a draft are kept as completed uploads, without their previews.

A “Kept drafts” section appears under Sessions when there are drafts that no composer shows: one whose session has gone, one whose conversation changed so that the person has to say where it goes, a second draft of a session that already has one, a copy kept beside another window’s draft, and the text of a prompt the host did not take. It appears on both the desktop and the phone, and on the phone the recovery banner leads to it. Each draft can be moved to a session the person chooses. When its own session is listed it can also be put in that session’s composer, and what the composer held stays as a draft of its own. A draft can be discarded. Nothing there sends anything. If there are any drafts that this version cannot read, they will be kept in the draft store and the number of unreadable drafts will be shown in this section. This section will also be shown if the host is not available, although moving a draft to a session will require the host to be available in order to fetch the list of sessions.

If the prompt is too long to be stored, and it wasn't taken by the host (or nobody knows if it was or not), it will be held only in this window. It will appear in the "Kept drafts" list as held in this window only, and it will be lost if the application is closed. However, it can be copied. Also, when its session is listed and its composer is empty, the text can be copied to the composer, to be shortened and sent again. It will remain in the list until the person removes it, as it cannot be stored in the composer due to its length. However, check if the prompt was taken by the agent before sending it again.

Only one of multiple windows holding the same stored draft may send it. Pressing Send saves the stored draft once, at the version the window holds, and only the first window to do so sends the prompt. A window that finds the draft changed or gone is told that another window holds it, sends nothing, and keeps its text. If the store refuses the save for another reason, the window will send the prompt and keep the text in memory. This holds as long as the store is operational.

A prompt, a steer or a queued message waits while an action of the session has an unknown outcome, because sending the text again could run it twice. An interrupt is still sent. On the phone a prompt waits while any action of the session is queued, sent or of unknown outcome. Closing the tab and opening it again does not lift the hold on the desktop, and a request that was still on its way when the tab was closed is held too. A record that arrives after the tab is closed still settles its action. While the conversation is open on the desktop, or the session is open on the phone, and the host is reached, the application reads what the host recorded of each action that has an identifier and no outcome. On the phone the read goes over the session's own link, under the screen's opening, and only while the host says the opening is open. The first read is at once, the next follows four seconds later, and each wait doubles up to a minute while nothing changes. A hidden page, and a view that has been left, read nothing. The waits start again when the person opens the session, comes back to the page, or sends another action. A record that says the action was applied, refused or rejected, even if it only arrives later, lifts the hold. A record that says less never does.

A person who has checked what became of the earlier action can press "I checked; send anyway", which stands beside the reason. The reason says that the earlier action may still run, so the work can happen twice. The press sends a new action and never repeats the earlier one. The new request names the earlier action and the revision of its record that the application last read and showed, which is how the worker knows the person looked at it: a worker refuses a later prompt while an action of the session is uncertain, unless the request quotes the newest uncertain action and the revision of its record. If that record has changed since, or the application has read none, the worker refuses the request, the application reads the record again at once, and the next press quotes what it shows. On the desktop every action is listed with its status. On the phone the newest action is shown beside Send, and each earlier action that is not finished is listed under the reason with its own status, so the earlier action stays listed as unknown, except while the field is the program's keyboard. The button is offered only when every action that holds the session is of unknown outcome. If the first send is then applied, the words were done, and the text is not given back to the composer when the second send, to the same conversation, is refused or its outcome is unknown.

A prompt the host has only accepted keeps its stored draft until the host says it was applied or refused. If the host then says a prompt was applied after nobody knew what became of it, the application removes the stored draft. A composer that shows exactly that text for the conversation it was sent to is cleared too. If a second send of the same words, made before the host said so, is also said to be applied, nothing more is cleared, because the composer then holds what was written after the first. A send made after the host said so is the person's own. Text the person wrote since, and a draft that another window of the application changed, stay. A file the person added since also stays, finished or not, and a finished file stays stored with the composer's own draft. The text of the prompt is removed in the same way from the list of Kept drafts and from the text held in this window only. On the desktop, an action that is still pending when the application closes is forgotten, and the text of the prompt comes back as a stored draft that can be sent at once. On the phone, every action that is not finished when the application closes, including one whose request was still on its way, is restored as an action of unknown outcome and holds the session. The phone keeps with each the stored draft it was sent from, and the conversation it was sent to. It names the draft again when the text is stored under another one, whether the store took the text only after the send ended or the words were put back under the composer's own draft. When the host then says the action was applied, the application removes that draft if it still holds exactly the prompt's text for that conversation, whether a composer shows it or it is listed under Kept drafts. If a send made in this run still held that draft when the host said so, and put the text under another one, the application looks in that draft instead. A draft that is another one, or that the person has since sent to another conversation, is left, whatever its words. A prompt that the device held no stored draft for leaves nothing to clear, and neither does one whose text the composer's next write stores under a draft of its own, which the phone is not told. If the store cannot be read when the host says so, or a send made in this run before the host said so still holds the draft, the removal waits until the store can be read and that send has ended, in the same run: if the application ends first, the text comes back as a stored draft at the next start.

If the store will not remove the draft of a prompt the host took, the application writes the removal to a ledger beside the drafts, for the version it tried to remove. The next start makes the removal, so the text does not come back as a draft, unless the store still refuses or the draft has been changed since. A ledger entry belongs to one version of a draft. If the ledger cannot be written either, the removal is owed in this window only, and the text can come back at the next start.

Nothing claims contact, or its loss, before an answer says which. Until the first answer the
desktop's bar and the phone's say they are checking the connection, with no status dot, and a phone
session opened from a notification shows no banner about the host. A reason for a lost connection
that is empty or only spaces is no reason: the page takes it in as none, so both bars say they are
not in contact, and setup warns that no host is answering and that no reason was given.

Each raw terminal view, on the desktop and on the phone, reads the session's snapshot and says how
the host presents it: the session's output directly, or a viewport with the host's reason in the
host's own words. It reads the summary of its own attachment and no other, and a viewport whose
worker reported no reason says so, and is never shown as direct.

A view attaches only to a worker whose build it can read. A worker outlives an upgrade, and it
states its build and protocol version in its answer to the hello. The view reads that once the
worker has proved who it is, and attaches when the version shares this application's compatibility
level (the same major number and, below 1.0, the same minor number; the patch number never
decides). For a worker of another level, or an earlier one that states none, the view asks the
session for nothing: it ends, names this application's build and the worker's (a worker that
states none is named as an earlier build), gives the protocol versions it knows, and says to close
the session or open it with the application of the worker's build.

A raw view opens in view mode, which takes nothing from anyone: the program gets nothing from the
person, and the view moves its window over the session, up into the history, down the live screen,
and across a session wider than the view. On the desktop the wheel does it (Shift turns a vertical
wheel sideways) and so does a drag; on the phone, a one-finger drag. Four buttons, Up, Down, Left and
Right, move it a page at a time for a keyboard or a screen reader, and each is disabled where the
window can go no further. On a phone with larger text they wrap onto a second line.

Take control is the only way in, and its label says it is a takeover. The view asks the session for
its one input lease, which takes the keys from whoever held them, and a window in the history comes
back to the live screen. While the session answers, the view says it is asking. Once it has control,
the program gets the wheel on both platforms, as wheel events at the session's cell under the
pointer, one turn for each row of scrolling, in the encoding the program chose, and only while the
program reports the mouse. A wheel never becomes arrow keys. On the phone a one-finger drag turns
the wheel the same way, once for each row the finger crosses, at the cell under the finger, and the
terminal keys go to the program; while the view watches, they are disabled. When the program is not
using the wheel, control mode says so and points to Look around, which gives control back at once.
Control also ends when another view takes it, when the program starts reading keys in a form the
view does not send, or when the session refuses the view's input, and the view goes back to view
mode with a sentence on why. Every write under a lease carries its number in the view's input
stream, and after a refused write the view writes under that lease no more: taking control again
starts a new one. A view declares a terminal profile of its own, which the host has not qualified,
so it is always drawn a projection. The host's keyboard table gives that profile the encodings the
view's keys can be spelled in on every platform: the ordinary encoding, `modifyOtherKeys` at level 1
or 2, and the Kitty keyboard protocol's disambiguation and event types. A program that asks for
more, such as the Kitty protocol's report of every key as an escape code, keeps control from the
view, and the view says why.

The page names each key as its platform reported it: the key, the character it makes with nothing
held where the platform says so (Chromium's keyboard layout map, or else the key itself while
neither Shift, Caps Lock, AltGraph nor Option is held), the keypad key it is, the modifiers, the
locks, and whether it went down, repeated or came up. Native code spells the key through the
client's shared encoder in the encoding the program negotiated, and spells a release only for a
press it wrote in an encoding that reports releases. What an input method, dictation or a software
keyboard commits goes as text, once, when it is committed, and never as keys made up for it. A paste
goes as a paste, bracketed when the program asked for that. A chord with Command or the Windows key
stays the platform's, and so do Control-Shift-C and Control-Shift-V off Apple platforms. A key, text
or paste that cannot reach the program as it reads keys now, or before the view holds the session's
screen, does not go: control stays, and the view says why until a key, text or paste does go, in the
mode's sentence on the desktop and above the field on the phone, where it stays in view with a
software keyboard up. The page sends each input once native code has answered the one before, so
inputs reach the program in the order the person made them.

On the desktop the program's keyboard is an invisible field at the cursor's cell, where an input
method opens its candidates, and what the input method composes is drawn there in the session's
colours until it is committed. The field comes next after the mode button in keyboard order, a click
on the terminal that selects nothing puts the focus in it, and the terminal shows a focus ring while
it has the focus. Tab and Shift-Tab go to the program. Control-Tab and Control-Shift-Tab move the
focus to the next control or the one before, and stop at the first and the last. When control or the
view ends and the focus was last in the field or on the mode button, the focus goes to the mode
button, or to Attach again once the view has ended. Focus on Attach again goes to the mode button
once the view is open again, whether the person pressed it or the view opened again by itself,
unless a pointer pressed it: a pointer's press leaves the focus where the pointer put it.

A drag belongs to the view it began in: taking control, the view ending or the session changing
ends it without sending what it had not sent. The page never decides where the window is. Native
code sends one viewport report at a time, settles each move on the screen the host names for it, and
tells the page a move is settled only with a screen that holds it. Until then the page draws its last
screen shifted to where the waiting moves will put the window, so a move shows at once, and a drag
follows the pointer to the pixel. The footer says where the window is.

A session fits a window as narrow as 320 px. Its actions move below its title, in the same order
and at the same size, a long name or directory wraps whole, and the terminal's badges and footer
controls wrap inside the terminal.

While a phone shows the terminal, the composer under it folds into the terminal's bar. The mode, the
zoom and, in view mode, the four moves take one or two rows. The status takes two lines, one for the
warnings and where the window is and one for what the mode does and how the host presents the view,
each cut short until More shows all of it; a screen reader reads all of it either way. Then come the
terminal keys, and the text field as one line with Send beside it. Attachments are added in the
conversation. While the view controls the program, the field is the program's keyboard, in the same
place and at the same size: the draft waits for control to end, Send goes with it, and the field
says Type to the program where a placeholder would. A tap on a terminal key is the key's press and
its release, with the modifiers the row holds for it, and it leaves the focus in the field, so the
software keyboard stays up; a key a hardware keyboard reports as a key takes the row's modifiers
too, and what an input method turns into text, as Android's does with a hardware keyboard's letters,
neither takes them nor lets them go. In the field Control-Tab and Control-Shift-Tab move the focus
on or back in either mode. When control or the view ends and the focus was last in the field, on a
terminal key or on the mode button, the focus goes to the mode button once the bar is back, or to
Attach again once the view has ended, unless the person has put it on another control first;
Attach again does the same once the view is open again, unless a pointer pressed it. While a
software keyboard covers part of the session, the bar gives way to the terminal, its keys and the
field, and the field sits on the keyboard's top edge. The terminal keeps at least four rows at its
default size in any case: when the composer needs more room than is left, it scrolls from the
bottom, so the field stays in view. The host is told the grid the terminal's surface shows.

A selection in either raw view takes the session's own selection colours, except on iOS, which
draws its own highlight over a page's selection. On the desktop a copy gives the selected pieces as
lines laid out by their cells.

## The boundary

The window is a WebView and the WebView is not trusted. Section 13 of the specification fixes what
that means, and each rule is a fact about a file here rather than a convention:

- **The interface is bundled.** `tauri.conf.json` names `../dist`. Nothing loads application code
  from a service.
- **Only named commands.** `src/commands.rs` holds the whole surface as a table. Each command names
  one protocol method in its own body; the page supplies parameters and never a method, a path or a
  command line. An operation with no command cannot be reached from the page.
- **Parameters are parsed, not forwarded.** A command turns the page's JSON into the method's own
  Rust type before anything is sent. The canonical encoding is KR-CBOR-1, where an identifier is a
  byte string and a counter an integer; forwarding the page's JSON would put text on the wire where
  the host expects bytes.
- **A restrictive policy.** No remote scripts, no `unsafe-eval`, nothing framed or embedded, images
  only from the bundle or from bytes this application produced.
- **Markdown is rendered, not injected.** `src/markdown/render.tsx` turns an established parser's
  tokens into elements. It never produces an HTML string, so there is no markup to strip. Raw HTML
  in the source renders as the text it is.
- **Links are checked and opened by the backend.** `https` and `mailto`, and nothing else. A link
  in agent text is a button that asks the backend; the page never navigates, and it is granted no
  opener command of its own.
- **The window stays on the bundle.** The main window is built from its configuration with a
  navigation handler that refuses any top-level navigation away from the bundled interface, and on
  a desktop a handler that refuses new windows.
- **Signing in happens in the system browser.** The account commands take nothing from the page.
  The backend builds the authorisation request, hands it to the default browser (a loopback
  listener on `127.0.0.1:8765` takes the answer) or, on a phone, to the platform's browser-backed
  session, checks the answer and keeps the tokens in the device's secure store. The page is told
  where the device stands and never sees an address, a code or a token.
- **A remote image is imported only when asked for.** A remote image is a placeholder with its URL
  and an import action, and the import is one request, over `https`, with a declared size limit.
- **Exports are written where a dialog put them.** The page asks for a destination, the platform's
  own save dialog answers, and the backend remembers that answer for exactly one write. A path the
  page names is refused.
- **Pairing's secrets stay native.** The page types a code, or asks for the pasteboard, the
  scanner or a picture to be read, and is shown views: an invitation's service and proposed rights in words, an attempt's state, the
  grouped value both devices show, and a confirmation's description. It is never sent an
  invitation's text or secret, a key, a transcript, a challenge or a proof, and it cannot complete
  a confirmation: `owner.confirmation.complete` is a method only native code calls.
- **A hand-over's plan stays native.** The page holds a reference and nothing else.
  `owner.confirmation.request` and `grant.transfer` are methods only native code calls, and the
  transfer only after an owner device has answered.
- **Recovery's secrets stay native.** The page asks for recovery to be turned on and for the kit to
  be saved. The seed, the bundle's locator and the account's token stay in native code, and the kit
  is written to a destination the save dialog returned. `src-tauri/tests/recovery.rs` holds this
  one.

`src-tauri/tests/boundary.rs` reads those files and holds them to those sentences.

One hardening switch is deliberately off. `freezePrototype` freezes `Object.prototype` before the
page runs, and the terminal library assigns `toString` to one of its own namespace objects while it
is being evaluated; against a frozen inherited property that assignment throws and the window comes
up empty. The setting is written into `tauri.conf.json` as `false` rather than left out, so the
choice is visible where the rest of the boundary is.

## Pairing with a host

"Pair with a host" is where this computer becomes one of a host's devices, and it runs in native
code, in `src-tauri/src/device`. The page asks for a code, or for an invitation to be read from the
pasteboard, the camera or a picture, and native code does the rest with `kr-client`'s pairing
module:

- This computer's keys are in the platform's secret store, the Keychain, the Credential Manager or
  the Secret Service, under "KalaReach Companion". The name it offers a host is its host name.
- A code's tries are counted in `pairing-budget` in the application's data directory, under a key
  kept in the same store, so a restart, a reboot or a second copy of the application spends from
  the same five.
- The hosts it is paired with, and an attempt still waiting for its owner, are records in
  `pairing`, each written whole and renamed into place. They hold no secret.
- The service it pairs through is `https://reach.kala.to` until the person picks another, and the
  choice is kept in `pairing-origin`.
- The host its commands go to is kept in `command-host`, written whole and renamed into place, and a
  choice that could not be kept is not made.
- A phone that iOS started before its first unlock cannot open its records. The commands say the
  device is locked, and the records open at the unlock, or when the application comes to the front,
  without another start.
- On iOS the `pairing`, `pairing-budget` and `recovery` directories are kept out of the device's
  backup. Their keys stay on this phone, so a restore onto another phone leaves no records there,
  and the person pairs again.

## Where a phone's commands go

A phone has no host of its own. It pairs with one, and from then on the commands the page calls are
asked of a host it is paired with, over the connection this device is authorised for, with the
rights its grant carries and no more (`src-tauri/src/hosts.rs`). The first host a phone pairs with
becomes the one in use, and the Hosts screen lists every host it is paired with, each with "Use this
host"; a computer that reaches a host of its own keeps that one until a host is chosen. The choice
is remembered across runs and taken up again when the application starts.

The application says what is true at each moment, as `connection_state` and the `kr://connection`
event: connected, with the rights, or not connected, with why. A connection that ends is taken up
again after a pause that grows while the host does not answer, a host that accepts a connection and
then closes it is waited for as one that does not answer, and a command made while there is no
connection is refused as such. The host on a computer's own machine is reached in the same way,
whether it was not there when the application started or its connection ended. Each choice of host
has a number, and a task that keeps the connection of an earlier choice can neither install its
connection nor record its loss once a later one is made. The Sessions and Hosts screens read their lists again each time the connection
comes or goes, and show nothing of a host that is not the one reached. The inbox is one list across every host the phone is paired with. The host in use is read by the page; each other host is visited by native code (`src-tauri/src/inbox.rs`, the command `inbox_hosts`), over a connection of its own that the next visit reuses while it answers and that is let go when the host is forgotten or taken into use, while the Attention tab is shown and not otherwise. Each visit is bounded to ten seconds, so a host that takes the connection and answers nothing holds up no other host. A visit returns the host's whole inbox and the numbers of its sessions, that the host answered and refused with the refusal it sent, or that the phone is out of contact with it and since when. Rows are tagged with the name of their host once more than one host is paired, a tap on a row of another host takes that host into use before it opens the session, and the tab's count is the rows waiting for the person on every host. A host that does not answer, the host in use included, is drawn as a row of its own, "out of contact", with the time since this device last heard it and the words that its sessions may still be running. It is never counted among the failures, and the rows last read from the host stay below it, said to be from that read. A host that answers and refuses is another row, "refused", in the host's words and with what to do about them: it is in contact, so no loss of contact is noted or counted for it, and nothing it held before is listed. A host that revoked this phone, or whose grant for it ended, sends no refusal the transport counts as one (it answers as it does an unknown device, or closes the connection), so it is drawn as out of contact. Nothing is written to disk, and a host the phone forgets or begins to use is no longer visited. A connection the host withdrew is
replaced by one it admits, `connection_state` counts each replacement in `replaced`, and the window
says so once for each. Nothing is sent again for the person.

When a session screen loads on the phone, it opens that session before it asks anything about it: it picks a token and passes it, with the session and the share if it holds one, to `session_open`. The host opens the session on a connection of its own, under that grant, and says what the grant allows. Every command about the session carries the token. A token can be used once, and a command that names an opening another has replaced executes nowhere. The connection kept for the host alone serves the host's own reads, and the host refuses it every command that would reach a worker.

Each opened link is watched. If its connection is lost and the grant has not ended, the application reaches the host again as the same opening, after a pause that grows, and the page is told `reconnecting` and then `open`. If the share ends, the page is told `ended` with the reason, and no connection under another grant takes the link's place. If the host cannot be reached when a screen opens, the opening stands as `reconnecting` and the application keeps trying. A command made outside any screen, such as the inbox's or a kept answer's, goes over one of at most four links that the application opens under the pairing and lets go when they are idle. At most eight sessions are open at once, and leaving a screen closes its link once the mutations in flight on it have answered.

A raw terminal view of a paired host's session has a connection of its own, which the host opens for the session under the grant the screen runs under. The view belongs to its opening and ends with it. When only the view's connection is lost, the application asks the host again, on the opening's live link, what the opening allows, and the page opens a view again. The last screen the view drew stays, and nothing the person typed is sent again.

`src-tauri/tests/phone_sessions.rs` runs these paths against kr-controller's in-process host with a real session worker behind it, a second paired device holding a share, and a link whose connections a test can hold, refuse or drop.

Voice on a phone starts with a question: a host that holds no voice grant for the device refuses a
preparation, and the voice screen shows the host's words, every action the default grant permits
in the sentence the protocol states it in, and the sessions to choose. Allowing sends the sessions
and the default actions to the host as this device's own grant, which native code names, so the
page never holds the identity the host gave the device. The answer states what the grant permits
and any action the device's own access does not include, which the person reads before the call
is shown. When replacing the allowance ended a call whose close could still reach a worker, the
host's answer names the workers that have not yet confirmed the fence, and the screen names the
sessions still to confirm, and says when the answer left workers out, before the person goes on. A
call that ends says the same, and says when the host's answer gave no status for its workers that
the app could read. The allowance stays until the person changes it.

An invitation on the pasteboard, in the code a phone's scanner sees, or in a picture the person
chooses, is read by native code, not by the page. Only a phone has the scanner and the picker: the
pairing view says which sources the device has, and a computer offers the pasteboard alone. The
scanner is a full-screen camera view (CameraX on Android, `AVCaptureSession` on iOS) and the picker
is the system's own. Both decode with the platform's detector, Vision on iOS and ZXing on Android,
and the text of a code goes from the platform's half to Rust and no further. Printing a reading
shows its kind and never its text. The Android scanner's window is secure, so a screenshot does not
show what the camera sees. iOS has no way to keep a screenshot from being taken, so the iOS scanner
hides its preview when the application leaves the active state and while the screen is recorded or
shared, and cannot stop a screenshot. A screenshot taken while the scanner shows a direct
invitation's code can hold that code; the invitation is short-lived and is spent by one pairing,
and it does not pair a device by itself, since the host's owner approves the device against the
value both screens show. The page is told that an invitation was found, never what it says.

One intake runs at a time, and a new one ends the one before it. An invitation a phone read is
dropped when the application goes to the background (on Android, when it pauses), and so is a
picture still being read; a code the scanner or the picker decoded is handed over only by an
application that has been in front since it began, so one that left while the scanner was closing
gives the code to nobody. Taking the application out of the active state for the Control Center,
the Notification Center or a question the system asks, such as the one about pasting, drops
nothing. A scanner or a picker the system does not show within ten seconds ends the request. The
camera's failures have words of their own: the camera is not allowed, with a button that opens only
this application's page in the system's settings, the picture shows no code, and the camera or the
picture could not be opened. A phone keeps its screen on while the value to compare with the host's
shows.

A code invitation that names a service other than this computer's raises the system's own alert,
modal to the companion's window, before anything connects there. The alert names both services, and
declining it connects nowhere. Each change reaches the page as a view on the `kr://pairing` event.
The page reads each view, and the connection's state for the indicator in its top bar, only once its
listener is registered, and keeps a change it heard over a read that answers later.

`src-tauri/tests/paired_host.rs` pairs a phone with kr-controller's in-process host and then reads
through the paired connection: the host chosen first, the commands the grant allows and refuses,
a host lost and reached again, a host remembered across a restart, two hosts chosen between, one at
a time and two at once, and a choice that could not be kept.

`src-tauri/tests/pairing.rs` pairs this computer both ways against kr-controller's in-process host,
confirms one request as its owner and declines another. It calls the pairing commands the way the
page does, through the invoke path on Tauri's mock runtime, and keeps every answer and every
payload of the two events the application publishes. None of them carries an invitation's text or
secret, the code's secret characters, a challenge's identifier, nonce or digest, the owner's proof,
the transcript and bundle digests the owner approves, or a key of this computer, the owner or the
host, and a secret planted in one event is found by the same scan. It shows the page told when the ceremony a phone offers changes. The same suite runs the watcher
against two hosts that share a relay and against a host that answers nothing, and reads a code for
another service through a stub alert that declines and then accepts it. It reads a code through a
scripted scanner and picker behind the same seam, and shows that a reading never prints the
invitation's text, that an intake overtaken while it waited holds nothing, and that what a phone
read is dropped when the application stops being in front.

`scripts/e2e-pairing-device.sh` pairs a phone with a real host through the installed application's
own screens, on the iOS Simulator and on the Android emulator. The host is kr-controller's daemon
on the loopback interface, and it holds one session. The run shows a changed secret locking nothing,
the value the phone shows equal to the host's, the phone paired once the host approves it, and the
alert a code for another service raises, with Cancel contacting nothing and accepting contacting
that service once. On the emulator it also shows the scanner kept out of screenshots and fitted to
the largest text size, and the attachment picker on a phone whose camera the system has refused for
good: a host this phone is paired with takes no file from it, so every source is disabled and the
screen says nothing of the camera. It then shows the paired phone as an owner device: the host asks
it to confirm one of its own requests and, separately, a second device it would add. A cancelled
prompt confirms nothing and leaves the request listed and the invitation behind it refused. On the
simulator the alert is cancelled once, and the system's Face ID is then sent a face that does not
match and cancelled at the system's sheet once it says the face was not recognised, so that Face ID
is shown to run and a refusal there to leave the request unanswered; on the emulator the system's prompt for the screen lock is cancelled.
The same request is then confirmed, with a matching face on the simulator and the PIN of the
emulator's screen lock, and the host spends that confirmation on the invitation. On the emulator the
PIN is taken away while the second device's request is listed: the button that confirms goes while
the request and its value stay, and the button returns when the PIN is set again. On the simulator the run
also pastes an invitation another application copied, answers the system's question about
pasting, and presses "Pair" on the invitation that is still held. The run then
searches the phone's log for the invitation's text and secret, and for the text and code of the
code QR; a log that could not be read, or that shows nothing of the application, fails that check
and is never counted as clean. It also checks the development package: the network security
configuration the verifier's library merges in keeps cleartext off, and the development build
names its own configuration so its development server, which speaks plain HTTP, stays in reach.

`scripts/e2e-android-release.sh` shows that the minified Android release build checks who it is
talking to, and that it can reach the deployed service. The build is signed with the debug key,
checked as a package (`scripts/lib/android-network-config.py`), installed on the emulator and driven
through its pairing screen. The check follows the manifest's name for its network security
configuration to the file the package holds under it and reads what the configuration permits: cleartext
traffic is off by default, it is permitted to the revocation-list hosts of the authorities the
deployed service's certificates come from (`c.pki.goog`, `e5.c.lencr.org` and `crls.ssl.com`, by
their exact names), and it is permitted to no host of this project nor any parent domain of one. It
first runs against configurations that must fail (one the manifest does not name, a disabled entry,
a parent where an exact host is needed, a broad exception, a permissive default), built from the real
output of the build tools, and stops if any answers wrongly. A local TLS server whose certificate a
private authority issued records what the phone does: it connects and ends the handshake after the
server's hello, as a TLS alert or as a closed connection (the two are recorded apart), and sends no
request, since the emulator trusts no such authority. That control is a refusal of an issuer, not of
a name that does not match, and it cannot tell a build that kept the platform verifier from one that
lost it. What tells them apart is a public origin whose certificate the system trusts and which
offers no pairing (`KR_RELEASE_PUBLIC_ORIGIN=https://example.com`): with the verifier the screen says
that the origin offers no pairing, and without the retention rule of `proguard-rules.pro` it says that
the service could not be reached. `--without-keep-rule` builds that second package and puts the rule
back. The run also makes one attempt, with a code no host holds, at the deployed service, whose room
admits a socket for any locator and reserves nothing for an unknown one: it ends with the words for a
code no host answered, and a build whose verifier cannot check the service's certificate ends with the
words for a service that could not be reached. A release build with no network security configuration
for the revocation-list fetch is that build: Android's revocation check needs a list over plain HTTP,
and the certificates Cloudflare serves for the deployed service name nothing else. The attempt is
sent only once the pairing screen names the deployed service as the one codes go through.

## Notifications on a phone

Each paired host has a row under its name on the Hosts screen that says where its notifications
stand and offers the one thing the person can do about it. Off, it says so and offers "Turn on
notifications". While the steps run, the words name the step, announced politely as a status and
never as an alert, since nothing is wrong. On, it says so and offers nothing: the system's setting
stops notifications on this phone, and only the host ends a destination. A stop says what happened
and offers "Try again", and "Open settings" when the system's setting is what the person has to
change. A computer has no notifications to turn on and the row does not appear.

The page asks four commands of the backend: `push_view`, `push_enable`, `push_refresh` and
`notification_route`, and is told of a change on the `kr://push` event. `push.rs` sequences the
steps for the host the person chose and holds the result in `push/push.json` under the data
directory: per host, whether the person asked, the authorisation identifier this phone issued for it
(so that asking again issues under the same one), the digest of the token the registration that last
turned the host on proposed, and the last outcome in words. The file holds no token, no key and no credential. `docs/delivery/README.md` ("What the phone does first") says what
the steps are. The application looks again with `push_refresh` when it starts and each time it
comes to the front, on whichever screen, because a person who left to change the system's setting
comes back to the screen they left. A tap on a notification opens the application, and
`notification_route` hands the page the screen once; the page goes to the attention screen, where
what needs the person is.

The platform plugin carries the commands the steps need to native code: the permission, the token,
the record of the registration being waited for, the limited key store, and the route of a tap. Its
Android half is `PlatformPlugin.kt` and the receiver in `native/android`; its iOS half forwards to
the application target through an adapter found by name (`KRPushAdapter`), as the voice call does.
The receivers answer a registration challenge through one function of the Rust library
(`native/platform/src/push.rs`), reached by JNI on Android and by C symbols on iOS. A debug build
reads the registration token and the gateway's origin from `kr-probe/push-request.json` in the data
directory, because a device run has no provider; a release build reads neither.

## An owner's confirmations

On a computer that is one of a host's owner devices, `src-tauri/src/owner.rs` asks each such host
every two seconds what it wants confirmed. Each visit ends within ten seconds, so a host that takes
the connection and answers nothing is out of contact until the next round and holds up no other
host. The requests head Attention, and each row has its title,
its description in one line, the time left, and a button named for this computer's ceremony:
"Confirm with Touch ID", "Confirm with your password" on a Mac without Touch ID, or "Confirm with
Windows Hello". A phone names its own: "Confirm with Face ID", "Confirm with Touch ID" or "Confirm
with your passcode" on an iPhone, "Confirm with your fingerprint or face" or "Confirm with your
screen lock" on an Android phone. A computer with no ceremony, Linux among them, shows no button and
says where to confirm instead, and a phone with no passcode or screen lock says that it cannot check
that it is you, and to set a lock or confirm on another device. A phone lists the requests on its
Attention tab, above its invitations, and counts them in the tab's badge. A request whose description does not match what it would authorise says it could
not be checked, and has no button either. A request for a device, an invitation or a hand-over of
control also lists what the grant allows, kind by kind, in a fact named "Allows". The line may say a
role instead ("who may act as the session's controller"), and the fact lists each kind the role
stands for (`docs/pairing/README.md`).

New requests are announced once, on whichever screen is open, in one message for all that arrive
together, with "Review", which opens Attention and moves focus to the first of them. Requests that
arrive while the message is showing join it in place, so whatever has focus in it keeps focus. "Not
now" sets a request aside until it expires, and it stays aside when the person leaves Attention and
comes back. For a device being added, the row shows the value both devices should show, and a screen
reader hears it spelled out one character at a time.

The button sends native code a reference and nothing else. Native code finds the request it listed
under that reference and asks the operating system, which draws the prompt and prints the
request's description in it:
`LAContext` on macOS, and Windows Hello through `UserConsentVerifier` for this window on Windows.
On a phone the platform plugin asks. An iPhone first shows an alert with the request's description
and Cancel and Continue, because Face ID completes when it sees the face and an alert makes the
person choose to go on; Continue starts `LAContext` with the passcode as its fallback. The alert
ends as not confirmed when the application goes to the background. An Android
phone shows the system's biometric prompt: a strong biometric with the screen lock as its fallback
from Android 11, or the screen lock alone when no strong biometric is set up, and before Android 11
a strong biometric alone. A phone with none of these confirms nothing. Which ceremony a phone offers
is asked of the plugin and kept for five seconds, so the person can set a lock in Settings while the
request is listed, and the page is told when the answer changes. Only this watcher gets the phone's
ceremony: revocation and settings sync have none on a phone. One request is confirmed at a time: a
review that starts while the person is being asked about another is refused and asks nothing, and a
phone's plugin answers a second request that reaches it with "not confirmed" and leaves the prompt
that is up alone, because the system's prompt keeps one callback for every prompt of an activity and
a second prompt would take the first one's answer. The prompt is bounded by the
challenge's remaining lifetime, and a ceremony that is never answered ends when that time and a
margin have passed. Only a confirmation inside it signs,
with this computer's key, and completes the challenge; when the time runs out the prompt is
dismissed and the answer is "not confirmed". Nothing on the page can answer the prompt, so a click
that desktop automation synthesises can start a review and cannot finish one. While a review runs,
the watcher does not connect to another host whose configuration shares the reviewed host's relay,
because that connection would close the endpoint the answer goes over.

## Revoking a device on a host you own

Revocation of other devices happens on the hosts that the local computer owns: it can revoke the
devices paired with a host it owns. This happens in native code, in `src-tauri/src/revocation.rs`.
Native code asks each host for a list of devices and, at the same time, reads its authority feed, so
a host that is asleep holds up the list once, even if the local computer owns multiple hosts, and
not once per host. The page just names a host and a device by the references that native code gives
it. It doesn't actually know any keys or identifiers, and it can't send `device.revoke`, as the
table of page commands won't allow that method. Instead, the one command that revokes performs the
revocation in native code.

There are two different ways of sending a revocation to a host, and the host that a request is for
decides which to use. If the host is running on the local computer, it will receive the
`device.revoke` method from native code. It will reply with an acknowledgement containing the state
of its dispatch barrier. The host will withdraw the connections it admitted before each revocation,
so the revocation is sent over a connection it admits then. If the host is any other host that the
local computer owns, it will receive the revocation over the authority feed. Native code signs a
request using the local computer's authorisation key and publishes it to the sync service. The host
reads the authority feed when a device connects and then again every 30 seconds. When it reads the
revocation request, it performs the revocation and publishes an acknowledgement to the authority
feed. A paired device can't send `device.revoke` to the host. So the authority feed is the only way
of reaching a host that is not the one on the local computer, whether it is reachable or not. All
revocations require first asking the person through the platform's ceremony. If the computer does
not have a ceremony, no revocations will be performed.

The revocation is completed only once the host's acknowledgement has been read. If the local
computer has published a revocation request to the authority feed and the host has not yet
acknowledged the revocation, the UI shows that the request has been sent, and nothing more. If the
host has acknowledged the revocation but it hasn't been confirmed by all of the session workers, the
UI shows that the revocation has been acknowledged by the host and how many session workers have not
confirmed the revocation. The same is shown if the feed says that the host finished but the host,
answering just now, does not list the device as revoked when it lists its devices. If the host
refuses to perform the revocation, the UI shows that the revocation was refused and the reason.
Acknowledgements are read from the authority feed. The authority feed stores the acknowledgements,
but does not interpret them, so they are the service's word for what the host answered, and not
something this computer can check.

A request published to a feed carries an announcement for the host. Native code seals it from this
computer's stored-envelope key to the host's, and the service places it in the host's mailbox beside
the request. The host reads its mailbox, finds the announcement and reads the feed at once instead
of at its next poll. The announcement says that the feed changed and nothing about what changed. It
expires 55 minutes after it is sealed. The service refuses a change whose announcement expires more
than an hour after the service's own clock, and it admits a request signed up to five minutes ahead
of that clock, so a longer expiry would let a computer with a fast clock lose the whole revocation.
A request whose announcement cannot be sealed is published without one.

The host announces back. When it acknowledges a request, it places an announcement that the feed
changed in the mailbox of the owner that published the request. It does so for the first
acknowledgement, and again when how much of the revocation the host's sessions have confirmed
changes. The answer itself is read from the feed.

This computer reads its own mailbox at the sync service (`src-tauri/src/mailbox.rs`) each time the
devices screen looks, but only when the screen reads at least one feed, which is when this computer
owns a host other than the one on it. A computer that owns no such host contacts nothing. A service
that asks to be left alone is left alone for as long as it asked, up to an hour. The pass has the
time a feed read has, and taking the lock is part of it. A stop of the mailbox never fails the
screen: the screen says in one line that announcements cannot be read and that answers to
revocations are still read from each feed.

The rules for taking an item are the shared reader's (`kr_client::mailbox_reader`). It opens an item
only against the stored-envelope key of a host this computer is paired with, holds the routing
record outside the box to the fields inside it, refuses an identifier it has accepted, and refuses a
payload that bears authority whoever sealed it. An item that opens is written down, and an
announcement that a feed changed is counted; nothing else is done with it. The accepted identifiers
are kept in `mailbox/replay.json` in the application's data directory, each until its item expired
and a day more, up to 4,096 of them. At that limit the reader accepts nothing more, says so, and
leaves the items on the service. A pass holds `mailbox/replay.lock` and does not wait for another
window of the application that holds it. A record of a version this build does not read, or one that
cannot be read, is left as found and nothing is acknowledged.

No answer a host gives says which sync service it reads its revocations from, as the host chooses
which to use with its own `authority.origin` setting. As the local computer doesn't know which sync
service the host is using, it publishes every revocation request at the sync service that it is set
to use. The sync service that the revocations are published to is shown on the screen. If the host
is using a different sync service, it will not see the revocation request and so it will not
acknowledge the revocation. The revocation request will remain in a sent state, so it cannot be
mistaken for a success. If the authority feed says that the host has been removed, the UI shows that
the host is not reachable by authority feed and the request is not published to any sync service. If
the host does not reply at all, the list of devices it previously sent will continue to be shown for
as long as the application is running. The time that the host last sent the list of devices is also
shown. Revocation requests will still be published to the sync service for these hosts.

When this computer sends a revocation, regardless of whether settings sync has started yet, the
revocation is written down before the request leaves. If it cannot be written down, the request is
not sent. Once the revocation has been written down, settings sync stops sending anything until the
device is removed from the shared settings, a step already under way included. From that point on,
nothing written after the revocation is sealed under a key the device holds. Once the device has
been removed, the previously unsent requests are sent, sealed under the key that follows its
removal. This record persists across restarts of this computer. The next step of any companion over
the same data takes the device out of the shared settings. Nothing takes that written-down record
back. Note that the revocation request might have reached the host even if the computer receives no
answer. Therefore the device will be removed from the shared settings in any case. In the case that
settings are shared with other devices, the person is told that the device was removed. If you
revoke a device, this computer will remove it from the list of devices sharing your settings. It is
out for every device that shares them. If another device that shares your settings adds it again,
this computer will again remove it. Pairing the device again does not bring it back. If you attempt
to revoke a device, but this operation fails, this computer will remove it from the list of devices
sharing your settings nevertheless, because the revoke request may have reached its host. As long as
a host lists it as paired and none reports it revoked, this device will be listed on the account
sheet, separated from the devices that have never had your settings. You can select it by pressing
the button “Share again” in its row. This runs the ceremony on the respective platform, with the
reason “Share your settings with”, the device's name and “again”. If the ceremony succeeds, the
computer asks the hosts again and then makes one write: it records the addition of the device and
takes back the membership’s record of the revoke. If the addition isn’t accepted, it leaves the
record of the revoke as it was. The addition succeeds only if at least one host still lists the
device and none lists it as revoked. A device that a host reports as revoked is not offered, and
neither is a device with a revoke request recorded in a host’s feed, because the host may carry the
request out, or may have carried it out and be asleep. A device that was never shared with is kept
out in the same way. The computer records each request it publishes in a host’s feed, by the
request’s own identity, before it sends it, and lets the record go only when the service answers
with a refusal it names, which it makes before it acts, or when the feed shows that the host refused
it because this computer has no owner authority there or the host does not know the device. The
computer lets nothing go in these cases: a feed that does not show the request, a restart, a host
that is asleep, an answer from the service that was lost, or a change of the sync service this
computer uses. The computer keeps the record when a host has acted on the request or refused it
because an earlier revocation covers it. A request that the computer cannot send, because it cannot
first make its hold on the settings durable, is not kept. Until the record goes, the account sheet
names the device with the words “A revoke for it is on record here, so it is not offered again” and
offers no button for it, and the command to share with it again refuses it, a request published
while the person was at the dialog for sharing again included. When the person forgets a host, the
computer lets go of the requests it recorded for that host’s feed. If a view finds that a device is
revoked, either because a host's feed contains a revocation signed by this computer or because the
host on this computer lists it as revoked (regardless of who revoked it), the device is taken out as
described above. Note that there is no way to stop a send of settings or drafts that is already on
its way.

The Devices screen, which appears after the Hosts screen in the desktop navigation, shows one card
for each host with the card for the local host (that is, the host which is on this computer) first.
Each card contains information about how requests reach the host and, if they do so via a feed, what
is currently in that feed including when the host most recently acknowledged requests, how many
requests are still waiting for the host, when the host most recently read its feed and whether the
feed has removed the host. In each card is a row for each device showing the device’s revocation
standing in words, along with a status badge indicating whether the status is sent, acknowledged,
revoked or refused. A request which hasn’t been acknowledged yet is never called revoked, and a
revocation is not considered done until the host has acknowledged it and every session has confirmed
it. A request which appears to have been acknowledged but whose device doesn’t actually appear in
the host’s own list of revoked devices is considered acknowledged, but the status text will
additionally say that the device needs to be revoked at the host. If the host’s feed is currently
unavailable to this computer, the device’s status will be whatever it was when the application most
recently read the feed, along with when that was.

The button in a device’s row is labelled “Revoke with Touch ID”, “Revoke with your password” or
“Revoke with Windows Hello” as appropriate, asking the user to perform the local computer’s ceremony
in order to revoke that device. There’s no need for a second confirmation (“Are you sure?”) because
the operating system’s dialog box will state which device is being revoked and on which host. If the
local computer doesn’t have a ceremony, no button will appear and the screen will say so. If the
feed has removed the host, or if the host’s feed is currently unavailable to this computer, or if
this is the local host and it’s not currently responding, no button will appear either and the card
will explain why. If a revocation request has been refused by the host, it’s possible to revoke it
again, but only if it was refused because an earlier revocation covers it, and the button then
begins “Revoke again”; if it was refused for lack of owner authority, the row will tell the person
to revoke the device at the host instead. If a revocation doesn’t go through, the row will say why
and the screen will look again (since it’s possible that the request still reached its host despite
the failure). Focus then goes back to the revoke button, unless that look finds the request sent, in
which case focus will be set to the status text for that request instead.

The screen will automatically look again ten seconds after the last answer, but only while a request
waits for its host: one that has been sent and not yet acknowledged, or one that a host reached
through its feed has acknowledged and not finished. (The screen only makes one look at a time, in
order to allow for hosts which may be slow to respond, and their answers are shown.) Each look will
connect to all the hosts that it lists, since a host reads its feed when a device connects. A hidden
screen will not look again until it has been shown. Since the local host answers each revocation
request as it is asked, there is no need for the screen to look for it; instead, the row of a device
that the host has acknowledged but not finished offers “Check again”. Any acknowledgement,
completion or refusal of a request, any change in whether the host’s own list agrees with an
acknowledgement, and any failure to revoke will be announced via a live region, and when a
revocation request is sent focus will be set to the status text for that request. Nothing on the
screen moves. This screen does not exist on phones, since a phone has no ceremony to confirm with
and so revokes nothing.

## Sharing a session

There is a "Sharing" tab in the settings of a session. It lists who has access, and then has a form for sharing the session.

The list contains the grants the host holds for the session. Each item shows: the device name, the role of the share (spelled out), the end time of the share (either the end of the share, or the end of the device's pairing, whichever comes first), and (if appropriate) buttons to either withdraw the share (if it is not yet accepted), or revoke the share (if it is active). If the share is active and carries `session.share`, it also has a "Hand over control" button. Owner devices are also listed, as having access whatever is done to a share.

When a share is revoked, a separate item is added to the list (the original share is removed when the grant is resolved). It shows when the share was revoked, the authority revision the host gave the revocation, and how many workers of the session have not yet confirmed that the share has been revoked. There is also a "Check again" button, to make a new request to revoke the share, which asks each worker again, and a "Dismiss" button, to remove the item from the list. The item says the same whether the result came straight from the host, from a background repeat by the native code, or from a user-requested repeat, except that a hand-over recovered in the background, or after the page started again, cannot name the device that gave control up.

The form offers only what the host would take. A device that is an owner, whose pairing opens every session, or whose pairing has ended is not offered, and its row says why.

The lifetimes shown in the share form are only the lifetimes that will end before the pairing with the selected device ends, minus ten seconds (to account for the time taken to make the request). When the pairing would end before one of the lifetimes does, "Until its pairing ends" is offered as well.

The "Reviewer" role is not offered. If the selected role has consequences, or the invitation lets the recipient answer the agent's questions, the "Invite" button is not enabled until the user has confirmed that they understand the consequences by ticking a box. The tick box is reset every time any setting in the form is changed, even if it is changed back to its previous value.

With the live view on, the page reads the lines on the session's screen through the session's own worker and shows them in a scrollable box (scrollable both horizontally and vertically, in case the screen has lines longer than the box). Control and direction characters are made visible. A screen the preview had to cut cannot be shared. The host writes the invitation with the screen it kept. After the share is made, that screen will be compared to the screen shown to the user, regardless of whether the result came directly from the host or as a result of repeating the share. If the screens do not match, the host's copy of the screen will be shown, and a "Withdraw" button will appear to withdraw the share. If the application is started again before the result of the share is read, the user's copy of the screen will no longer be available, so they cannot be compared. In this case the row of the attempt says so and offers Ask the host and Withdraw. Once the host answers, a message says the two could not be compared, shows the host's copy of the screen, and offers "Withdraw".

Device names are whatever the device's owner typed, and may contain characters that affect the direction of text. To prevent these being used to confuse the user, a character that affects the direction of text is shown as its character code wherever the page says the name.

The four actions that change who holds a session (inviting a device to a share, accepting an invitation, withdrawing or revoking a share, and handing over control of a session) are attempts, and native code keeps its word about each one. When an attempt is made, the native code will create a file in a directory for the host under `kept-attempts` in the application data directory, containing the request and the name of the host it is for, and the user that the attempt is for. It will then send the request. If the host replies directly, the reply will be returned from the method that made the attempt, and no record is left. If, however, the attempt does not get a reply, the method that made the attempt will return it as unfinished. The native code will then, in the background, ask the host again with the same request, up to three times, each on a connection opened for it, and then read the state from the host to determine the result. While an attempt has not yet finished, it will be shown in the list of attempts, and the page says until when it can still happen; once that time has passed it says the attempt may have happened and that only the host can say. There will also be buttons for Ask the host, which is always the person's choice and sends nothing but an exact repeat, and Hide, which takes the row out of view and releases nothing. Hidden attempts will be counted, and will be shown in a list of hidden attempts, with a button to show the attempt again. A record that this build cannot read is counted on the page and left as it is. The user's choices to show or hide attempts will never be overridden by the native code, even if the native code writes to the kept attempts. When an attempt finishes, it will be shown, even if it had previously been hidden.

A hand-over that is still being asked for can be cancelled, but cannot be hidden. A hand-over left behind when the application was started again while one was being asked for will have lost its reference, and so cannot be completed. It will be shown in the list of attempts, with a button to cancel it, removing the record of it and allowing another hand-over of the session to be made.

Even if the host has stopped listing an invitation, the application can send an acceptance of it, if it has listed the invitation before. The host would know if it was withdrawn, expired, already used, or belongs to a session that is no longer open, and the person is told its answer in the host's own words. However, if the application has not listed an invitation, the application refuses it without sending an acceptance to the host.

It is not possible to make a second invitation to the same session and device, or a second hand-over of the same session, until the first can no longer happen, even if the attempt is hidden or the application is started again. However, the attempts will not be repeated after the application is started again unless the user requests them to be.

An attempt is said not to have happened, as far as the host shows, only after the bound that the window sets has passed, and an attempt whose outcome cannot be told is shown as unknown. If the host's result carries something the person is owed (for example, the screen the host kept with a live invitation, or how far the session workers have got with a revocation), the record stays after the attempt ends, and the host can still be asked for the result until the page has shown it, so a restart before the page read it loses nothing.

A hand-over asks the host to describe the plan and put it to the owner devices, and sends nothing that changes who holds the session. The page holds a reference to it, and the plan, the action and the parameters stay in native code. It asks every second whether an owner device has answered, and when one has, native code checks that the plan the host described names the session, the grant and the receiving device that were asked for, and sends the transfer once. The hand-over leaves native code's table in the same step that keeps the record of the transfer, so a cancel either came first and nothing is sent, or comes later and finds nothing to cancel. The panel tells the person how the send went whether or not it is still on screen, and leaving it before the send lets the hand-over go. What the page has been told of a result is kept for as long as the page lives, so leaving the tab does not lose it. A hand-over that has not been answered when its challenge runs out is shown as that, and Ask again starts a new one. If the host does not answer the request for the owner devices' confirmation, only its answer to the first request is final. When the repeats run out, the page says it is not known whether an owner device was asked, and that one can still be shown the request for up to two minutes, though nothing this application sends will hand anything over.

## Settings and settings sync

The colour mode setting can be set in one location: `settings.json` in the application data
directory. When the application's window is opened, the colour mode is already in the window's
document, as data the page reads and never code it runs, so the initial draw of the window will be
in the correct colour mode. The colour mode is changed by a command, which writes the new colour
mode to `settings.json` before doing anything else, or by a sync step that follows another device.
No state is stored in webview storage, all reads will be from `settings.json`. If multiple
companions are running on the same device, a choice made in one is found by the others. When the
colour mode is changed, it will take a lock on `settings.lock` to prevent race conditions.

The settings can be synchronised across devices, which stores an encrypted copy of the settings in
an encrypted collection on a settings sync service, which another device that is a member of the
collection reads. Syncing is disabled by default, to enable it navigate to the Account sheet and
turn it on. No account is needed, requests to the settings sync service are authenticated using the
signature of the device making the request, no token is ever transmitted. The collection is stored
on the settings sync service specified by the sync service setting at the time sync was turned on.
Changing the sync service setting later will not migrate the collection to the new sync service. The
logic for settings syncing is in `src-tauri/src/settings/sync.rs`, which records the collection
under `settings-sync/` on this computer before any requests are made, and each step holds a lock on
`settings-sync/sync.lock` while it runs. A sync step is run every 5 minutes while the application is
open.

A sync step performs the following steps to bring the settings on the device and the settings sync
service into a consistent state: If there is a pending response from a previous write, query the
settings sync service for the response. If a version another device wrote is waiting for a choice
and differs from this computer's settings, nothing else happens until the person chooses. If the
settings on the device differ from the last known consistent state, perform a write to the settings
sync service to publish the changes. The service refuses the write when something was written to it
in between, and keeps what the other device wrote beside this device's own for the person to choose
between. Otherwise perform a read from the settings sync service to sync the settings on the device
to any changes made by another device. A clock never decides between two devices.

When there is a conflict between the settings on two devices, the user is prompted to resolve the
conflict in the settings card of the Account sheet. The conflict is resolved inline, with each
option rendering the settings as they would appear. The options are not selected by default, the
first option is the settings currently on the device. Each option shows a time, only so the person
can recognise it. The buttons to resolve the conflict are labelled with the action they will take.
Once the conflict is resolved, all other versions of the settings are discarded. If the service
cannot be told of the choice, the choice stands and the next sync step sends it.

Drafts can be kept in step between devices through the same collection as the settings. This is a
second choice, made in the settings card of the Account sheet once settings sync is on, because an
unsent prompt is more sensitive than a colour mode. When this computer publishes a draft, it is
sealed with the collection's key, and only this computer can change it. A draft that another device
published arrives as a copy kept beside this computer's own drafts. It is never opened in a composer
and never sent. The logic is in `src-tauri/src/settings/drafts.rs`, and its records are under
`settings-sync/drafts/`.

A draft is written for a session, a session lives on one host, and each host has its own privacy mode. So each host's drafts are published through a sync store of their own, fenced at that host's privacy generation. The Settings Store is not fenced because the Colour Mode does not contain any Session Contents.

This computer does not guess which host a draft is for from the host that happens to be connected when the draft is saved. It asks the connected host whether it holds the draft's session, with `session.read`, and keeps the answer together with the session it was about. If a Draft is sent to a Session that belongs to another Host, the Draft has no Host until the answer for the new Session is received. This computer reads a host's privacy mode with `host.info` over the same connection. This information can be read by any paired device, and does not require the right to manage a host. If the host is changing its privacy mode, the computer will consider it private until a later answer. If the host runs an earlier build, and does not include its privacy mode in `host.info` (it will only provide this information to a device that manages it), the computer will ask the host `privacy.status`, if it has the right to do so. If the computer is unable to read the privacy mode of the host (because it is not connected to it, because the host runs an earlier build that tells it nothing, or because the host does not answer), the computer will treat the host as private. Drafts for a private host, for a host that cannot be read, and for a host that has not yet said it holds their session stay on this computer, and the settings card says how many and why.

Every answer from the service is held until this computer has read the host's privacy mode again and moved the host's store to it, unless the store is already fenced. A host that went private while a publication was out therefore has the answer discarded, and nothing is noted of the draft. A host that cannot be read at that moment is treated as private until the next read: the draft is noted as published when the service applied the write, and what an answer brings down is withheld. A store that cannot follow a host whose state was reset is fenced at the generation it holds, in the same way. Publications that left without an answer are asked about at the start of every pass, in the store of every host that has one.

When a Draft is sent or thrown away, the Service is informed so that it can remove the Draft. Because only 256 objects can be stored in a Collection, it is important to remove the Drafts. The removal is stored in the `removals.json` file before the Draft is removed; if the removal cannot be stored, the Draft is not removed. The removal is owed until the service has made it, and it is retried while the host is private or cannot be reached. Each removal is compared to the newest known place for the Draft on this computer, which can be a Note for the Draft, a Note in the removal, or a place in the Sync Store of any Host for a Publication. A publication that has not been answered is waited for, and one that ended without an answer is found by asking the service what it holds. The removals do not need allowance from the Settings Sync. So if the allowance is spent, the removals can still be done.

A second device of the same person joins the settings in two steps, and the person has to be present for both. On a computer that holds the settings, the account sheet lists the devices the person's hosts list as theirs that do not hold the key yet. "Share settings" runs the platform's ceremony with "Share your settings with" and the device's name as its reason. After the person confirms, the hosts are asked again, and the key moves on to a new epoch that includes the device only if they still list it and agree on its keys. On the other device, the sheet offers the settings once the sync service lists them for this installation, named for the device the collection was started on, and "Join" runs the ceremony there. Only macOS and Windows have the ceremony, so a computer on any other platform, a phone among them, is offered neither "Share settings" nor "Join", and the sheet says to do it on a Mac or a Windows computer; and a computer that holds the settings offers no device on another platform to share with. A computer that holds no shared settings, or was taken out of them, looks for an offer when the person presses "Look for my devices" and, with settings sync on, when the sheet first opens; with settings sync off it sends nothing to the service until they press. A computer that starts settings sync of its own cannot join another's yet, and cannot leave its own, so to share settings between two computers the person starts settings sync on one of them only and joins from the other. While an offer is waiting, the sheet says this beside "Keep settings in step".

A device is added only when a host lists it with all four keys and with the right to manage the host, a right that has not run out with its grant, and when every host that lists it gives the same stored-envelope key. The page names a device by a reference and never holds a key. The sheet takes a device out after one question and without a ceremony, and so does the next check when a host reports the device revoked. A device taken out of the collection keeps every key it held, so this computer believes only what was sealed since the last time it saw a device taken out. It works that out from the devices each key record lists, by both their keys, and when it cannot tell what happened between two looks, because more than one record passed, it believes only the newest epoch. The settings sealed earlier are sealed again by any member that holds them and last agreed with the service about them, not only the one that wrote them, once the service still holds exactly what that member agreed with. A device that joined after, and a member that cannot read what the service holds, wait and say so, and write nothing over it. When the service holds settings from before the floor that this computer cannot believe, because the device that wrote them was taken out or this computer missed the records in between, the member waits and writes nothing, and the next change the person makes here goes over them and says which writes it went over: every write after the last one this computer read, up to the one it replaced. A device that holds one of those writes keeps the change beside its own settings, and asks its person to choose, which it also does for a later change made from the settings that went over it, or chosen beside it. A device that holds none follows the change and is asked nothing, so the last write of a device taken out is offered to nobody. A computer that holds no settings of its own asks the service what it holds at every step before it makes its first, and waits while it cannot read the answer. Drafts sealed earlier are not asked for again by the devices that did not write them, until their writer changes them, and a device that cannot read one reports nothing.

This computer asks the host it is connected to over the connection it already holds, when its grant manages that host, and every other host it owns over a connection made for the question, all at once, and no more than once a minute while nothing is pending. A host that does not answer says nothing about any device: the membership is told that one was silent, and a device that this computer's hosts vouched for before, and that no answering host mentions, is not taken out for it, while a device an answering host mentions is judged by what that host says. Silence keeps such a device in the shared settings and the next key is wrapped to it, but it accepts, opens and adds nothing: a record, a key or an addition still needs a host that answered to list the device, and a record from a device that this computer's hosts vouched for and only the silent host lists waits for that host, with nothing built over it or over any record on top of it. A host that stays silent therefore keeps the devices only it lists in the shared settings, until it answers or the person unpairs it, and a computer does not join the settings while a host of its own is silent or refuses to list. A host that answers that it will not list its devices to this computer has answered, but says nothing about the devices only it lists, as a silent host says nothing, so they are kept in the same way. When no host lists, because every host it owns refuses or one refuses and another is silent, this computer checks nobody, publishes nothing and says so, and takes nobody out for it. A host that refuses the connection for another reason, or does not find this computer paired and so ends the connection before it answers, counts as silent. A computer none of whose hosts answers checks nobody and adds nobody.

## The sync service and recovery

The sync service is a setting of its own. It is the managed service, `https://reach.kala.to`, until
the person picks another, and the choice is kept in `sync-origin` in the application's data
directory. It is not taken from the account's origin, the pairing service or a host. The Account
sheet shows it with a Change control, as the pairing screen does for its service, and accepts an
https origin or an http one on this computer.

Recovery keeps the owner's seed on this computer and an encrypted bundle at a stable locator on the
sync service. `src-tauri/src/recovery.rs` does it with `kr-client`'s `BundleStore`, which owns the
bundle's rules: writes that compare the revision they replace, and a record of any write whose
answer never came back.

- Turning recovery on writes `recovery/recovery.json` first (the service, a locator drawn for the
  bundle, and whether the first write is known to have landed), flushed to disk before the first
  request. It then makes the seed and keeps it in the device's secure store, and puts the first
  bundle at the service. A kit exists only once that write has landed. A start that did not finish
  goes on with the locator it began with, and a bundle that landed unrecorded is read with the
  seed and kept; a bundle the seed does not open is left alone and no kit is offered for it.
- Each step holds `recovery/recovery.lock` for as long as it runs. A second companion on the same
  machine waits for the step in hand, so two of them never each draw a locator and commit a bundle
  of their own.
- A write whose answer never came back shows as unsettled, and nothing else is written until the
  person settles it. Settling asks the service to fence the write's identity, and reads the bundle
  back where the fence does not say what became of the write. A restart keeps the write unsettled.
- Saving the kit writes the seed, the locator and the service to a file at a destination the save
  dialog returned. The file is flushed to disk and, on Unix, has the owner-only mode (0600); on
  macOS its access list is removed first, and the save fails and leaves the file's contents as they
  were when the list cannot be removed. On Windows a new file has the permissions of the folder the
  person chose, and a file that already existed keeps its own. The page is sent none of its
  contents.
- Saving the kit as a QR code draws the kit's own text, the document a person could have typed, at error correction level Q as an SVG with a four-module quiet zone, and writes it where the save dialog put it with the same owner-only rules as the text kit. The file has a print size, about six centimetres across for a typical kit. The code holds the whole kit, the seed included, and the card says so. The SVG text that holds it is built in one buffer, sized beforehand and cleared when it is dropped; the encoder's own copies of the kit (the bit buffer and codewords it builds from the kit text, and the `qrcodegen::QrCode` it returns) are ones this program cannot clear, and they are freed without being cleared.
- An offline copy is a file of ciphertext. The card lists the archives the recovery bundle names, each with the newest generation the service holds of it, and writes the bundle alone or the bundle with one archive's newest generation to the file the save dialog returned. This computer reads the service with the account to make it, authenticates the bundle with the kit and opens the archive's manifest in memory to find the objects it names; nothing decrypted is written or sent, and the file holds no kit text. Reading the service is not a host's privacy-mode matter, so privacy mode does not stop it. The file opens with the kit alone, with `kr backup restore --from-export`. An archive of more than 256 MiB of ciphertext is refused by name: it has no offline copy and restores from the service only, so with the service gone it cannot be restored.
- Covering the host on this computer (`recovery_cover_host`, `Recovery::cover_host`) is how the
  host's backup writer is made recovery-enabled. A kit opens the archives a host makes only if the
  host was set up under that kit's recipient, so naming the writer in the bundle is not enough, and
  the command does both. It reads the host's status over the connection to the host on this
  computer, refuses to declare anything when the host cannot be covered as it stands, commits the
  bundle naming the host's archive, producer and writer, and then sets the host up under this
  computer's recovery with the very bytes that landed. The Recovery card says the host is covered
  only after the host has said it is set up. The page names nothing but whether a replacement is
  asked for. A host that selects no storage service or another than the bundle's, that holds no
  usable sign-in, whose setup has not ended, or that was set up under another kit is left as it is,
  and the card says which. A host set up under another kit keeps its archive and its recipient, so
  the only way to put it under this recovery is a replacement: the card offers it as a second,
  confirmed choice, and the host then starts a new archive under this recovery. What it backed up
  before stays at the service and opens only with the earlier kit; the host stops adding to it and
  does not remove its old backups. A host that declines, or refuses the call, has recorded nothing,
  so the bundle is written again without the archive it was made to name, and the card says why the
  host declined and that its backups were not changed. A setup whose answer was lost keeps its
  entry in the bundle until the next try finds the setup if it landed; if it did not land, the
  entry names an archive the host never made, which a restore lists as holding nothing. A setup is
  told from another by the recipient's public key that the host's status carries, and not by the
  fingerprint, which is 40 bits of it: the fingerprint is for people. The card covers the host on
  this computer only: a paired host cannot be asked for its status.

The bundle is reached with this device's signature and the account's token, and the token goes only
to the service the account is signed in to. When the sync service setting names another service,
no request is made and the refusal names the setting. A sign-in that does not carry the right to
write the account's backup storage sends nothing either, and the person signs in again with that
right. The record names the service the bundle is kept at, so choosing another sync service later
does not move the bundle; the kit still points at the service it was made for, and the Account
sheet says so. A phone shows the setting and offers no recovery.

## What a phone reads once

A record the start reads once from a file is marked unread when the system refuses the read, never taken for an empty one. It is read again at its next use, and nothing is written over it before.

## The design system

The design system is Newsprint, with light, dark and system modes. `src/styles/tokens.css` holds
every colour, the motion durations and the target sizes; `base.css` the document and the type scale;
`components.css` the components; `views.css` the screens. A component never names a literal colour,
so light, dark, high contrast and reduced transparency are one implementation.

Three rules run through the motion:

- A transition is 120 ms for a press, 160 ms for a state change and 200 ms for a surface arriving.
  Nothing is slower.
- A keyboard-driven change is not animated at all. A key is repeated hundreds of times a day, and
  an animation on one reads as the application hesitating.
- Streamed text and the terminal never animate.

The one gesture is the settings sheet. It tracks the pointer one to one, resists past its own edge,
decides from the velocity at release, and can be caught and reversed mid-flight, because it runs on
a critically damped spring that starts from the value on the screen. With reduced motion nothing
moves by itself: it cross-fades in and out. A drag is still the person's own motion, so the sheet
follows the pointer and back, stops dead at its edge rather than stretching past it, goes back at
once when let go short of a dismissal, and fades where a dismissal leaves it.

On the phone the settings are not a destination. A session's top bar carries a Settings control
that opens the same sheet over the session, with the appearance choices: the session stays behind
it with its draft, and the choices sit three across while each names itself whole and wrap onto
another row at larger text. The system's back closes the sheet first and leaves the session on the
next. A sheet rests clear of the bottom inset the platform reports.

Where the platform pans the phone's page to keep a focused field in sight, the shell goes with the
visual viewport by as much as it was panned, so nothing of it is above the screen, and what the
keyboard takes of the height is at its foot, the composer above it. This holds where the platform
shrinks the layout viewport to what is visible while it pans, as iOS does the first time a field
takes the focus. Where the session is taller than the room above the keyboard (larger text, a phone
on its side), the session scrolls and the field being typed into is scrolled to, rather than asked
to scroll itself into view, which would pan the page again: the field rests on the keyboard's top
edge and the rows above it go out of view first.

At larger text sizes the phone's inbox breaks a long word, such as a path or a command, where its
row ends instead of running past the screen, and the count on the Attention tab is a circle that
grows with its digits, up and away from the tab's glyph.

## Running it

From the repository root:

```sh
pnpm install
pnpm -C apps/companion tauri dev
```

That builds the interface, starts the desktop shell and connects to the controller on this machine.
Without a controller the window still opens and says it is not in contact, which is the state it
has to have anyway.

The interface on its own, in a browser:

```sh
pnpm -C apps/companion dev
```

## Checking it

```sh
pnpm -C apps/companion lint        # ESLint, type-checked
pnpm -C apps/companion typecheck   # both projects
pnpm -C apps/companion test        # unit and component tests, and the semantic-display benchmark
pnpm -C apps/companion e2e         # Playwright, against the built bundle in Chromium and WebKit
pnpm -C apps/companion build       # the production bundle
cargo build -p kr-worker         # the worker the backend's session cases start
cargo test -p companion-tauri      # the backend, including the boundary
```

The push legs run on a device under the device lease: `scripts/e2e-push-device.sh ios` or `android`, with
`KR_WEB_TREE` naming a built web checkout. `scripts/e2e-push-android-receiver.sh` runs the receiver's
instrumented cases.

On macOS the same command opens real windows for two checks with a main thread of their own.
`tests/navigation.rs` holds what the web view does with the navigation handlers. `tests/host_events.rs`
has a scripted session worker push events on a link the application reached as it reaches a real
worker, and a page in a real web view, allowed only what the interface's capability allows, listen
for them through the event API as the interface does: it checks that the page receives each event in
order, with its stream, sequence and type, and its payload as JSON or as null.

On Windows the same command runs `tests/windows_hello.rs`, which reads what Windows reports about
Windows Hello and checks that the page is sent that ceremony or none. Its tests that raise Windows
Hello's dialog are ignored: they need a signed-in desktop with Windows Hello set up, and the file
says how to run them there. They check that the dialog prints the exact message the review gave
Windows Hello.

The end-to-end run builds a second entry, `harness.html`, which is the same application against a
host that answers without a machine behind it. The production build has one entry and does not carry
it.

Screenshots from the end-to-end run go to `/tmp`, named for what they show.

## Building the application

```sh
pnpm -C apps/companion tauri build
```

macOS is the first target. Windows and Linux compile from the same source; their packaging is not
covered by the checks above.

On Windows, with Microsoft's linker, the build links the application manifest into every binary it
makes, the test binaries included. The native dialogs need version 6 of the common controls, and a
binary without the manifest that selects it cannot start.
