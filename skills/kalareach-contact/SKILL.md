---
name: kalareach-contact
description: Reach the person running this KalaReach session. Use when you need a decision or a fact you cannot get yourself, when you are about to do something you cannot undo, or when work finishes and somebody should know. Provides ask_user, wait_for_answer, cancel_question and send_notification over the local kalareach tool server.
---

# Reaching the person

You are running inside a KalaReach session on this person's computer. They may be at the terminal,
or they may be on their phone. Four tools connect you to them:

| Tool | Use it for |
| --- | --- |
| `ask_user` | A decision or a fact you cannot get yourself |
| `wait_for_answer` | Waiting on a question you already asked |
| `cancel_question` | A question that has stopped mattering |
| `send_notification` | Something they should know that needs no answer |

## When to ask

Ask when the work genuinely stops without them:

- A decision you cannot make safely: which of two designs, whether to spend money, which account.
- A fact you do not have and cannot find: a credential name, a customer's real deadline.
- A step you cannot undo: deleting data, force pushing, sending a message to somebody else.

Do not ask for anything you can settle yourself. Make a reasonable, reversible choice, carry on, and
say what you assumed. One well-formed question is worth more than five that interrupt.

## How to ask

Make the question answerable in a few seconds by somebody who is not looking at your screen.

- Put the decision in `question` and the background in `context`. Keep context to what turns on the
  answer: what you are doing, what you found, what each option costs.
- Choose the form that matches the decision. `confirm` for yes or no. `select` for two to twelve
  named options. `input` when any of them would be a guess.
- Give every choice a stable `choice_id` and a label a person reads. The identifier is what comes
  back; the label is what they see.
- Generate a fresh unpredictable `request_id` for each new question. Reuse it only to retry the
  identical question after a failure: the same payload returns the same question rather than asking
  twice, and a different payload under the same identifier is refused as `ID_CONFLICT`.
- Set `agent_name` to something they will recognise. It is displayed as an unverified label beside
  the application identity the host verified.

Every `select` and every `confirm` also offers "Something else" with free text. The host adds it and
you cannot remove it, because the right answer is often none of your options. An answer that comes
back as `other` is free text: read it as free text. Never treat it as one of your choices and never
treat it as yes.

## Waiting, and not waiting

`ask_user` can wait up to 30 seconds. Use that only when you are genuinely stuck without the answer.
Otherwise let it return the pending question and call `wait_for_answer` when you have run out of
useful work.

`wait_for_answer` holds for up to ten minutes and returns the same question when the wait runs out.
That is not an answer. Wait again if the work still depends on it, or carry on and say what you are
waiting for.

A call that is asking or waiting and gets cancelled takes its question with it. If the person
interrupts you, or your client gives up on the call, the question is cancelled and they are no
longer asked. Ask again if you still need the answer.

**An unanswered question is never approval.** A wait that times out, a person who dismissed the form
and a question nobody has opened all look the same from here, and none of them is a yes. Do the
irreversible thing only when an answer says to.

`cancel_question` when the question stops mattering: you found the answer, the work moved on, the
person is answering something better. Leaving stale questions open costs them attention they will
spend on the next one.

## Telling them without asking

`send_notification` for work that finished, a failure you cannot clear, a run that needs their eyes
but not their decision. Give each alert a `dedup_id` so a retry does not become a second alert. It
asks nothing and returns nothing to wait on.

## What these tools are not

They reach the person running *this* session. They cannot list other sessions, read history or send
input anywhere. Answering `yes` here resolves this question and nothing else: it produces no
approval inside any other tool and widens no permission you did not already have.

Outside a KalaReach session every tool answers `NOT_IN_KR_SESSION` and creates nothing. Start the
agent inside a session (`kr new --attach`) and the tools work.

`TOOLS.md` has the exact parameters, results, error codes and timeouts.
