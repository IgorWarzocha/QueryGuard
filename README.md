# Is Your Chatbot Being Misbehaved or Tricked? QueryGuard Can Help!

Are you frustrated because your helpful chatbot is:

* **Going Off-Topic?** Answering questions it shouldn't, or getting sidetracked by users?
* **Being Tricked or Manipulated?** Users making it say or do silly, inappropriate, or unintended things?
* **Revealing Information It Shouldn't?** Accidentally leaking details about its setup or even parts of the documents it's supposed to use?
* **Wasting Resources?** Users submitting overly long, complex, or repetitive questions that drive up your chatbot's running costs (especially if you pay per message/token)?
* **Exposing a "System Prompt" or "Instructions"?** Users trying to figure out its core programming?
* **Just generally being abused by "cheeky" users or bad actors?**

If any of this sounds familiar, you're not alone! As chatbots become more common, people are finding all sorts of ways to misuse them. This can make your chatbot less effective, less safe, and more expensive.

## Introducing QueryGuard: Your Chatbot's First Line of Defense

QueryGuard is like a smart, friendly security guard for your chatbot. It's a software component that works silently in the background to check messages *before* they even reach your main chatbot.

**Think of it like this:** Your chatbot is a very smart and helpful expert (the LLM). QueryGuard is the receptionist or assistant who quickly screens visitors and their requests. If a request is clearly problematic, off-topic, or an attempt to waste time, QueryGuard can step in.

## How Can QueryGuard Make Your Chatbot Better?

By adding QueryGuard (or a similar system) to your chatbot setup, you can:

* ✅ **Keep Your Chatbot Focused:** Help prevent it from getting sidetracked by irrelevant or out-of-scope questions. This means it spends more time on what it's *supposed* to be doing.
* 🛡️ **Protect Against Common Tricks:** Make it harder for users to directly "jailbreak" or bypass your chatbot's primary instructions.
* 💰 **Reduce Wasted Costs:** Filter out queries designed to be overly long, repetitive, or computationally intensive, potentially saving you money on API calls to the main LLM.
* 🔒 **Enhance Basic Security:** Provide an initial barrier against users trying to extract sensitive information (like its system prompt) or make it perform unintended tasks.
* 🛠️ **Handle Known Gaps More Gracefully:** (Planned Feature) Allow for pre-defined responses to common problematic queries, so your chatbot doesn't just say "I don't know" to things it's not meant to answer.
* 😌 **Give You More Peace of Mind:** Know that an initial check is happening to catch common forms of misuse.

## How Does It Work (In Simple Terms)?

QueryGuard works by looking at the user's message before your main chatbot AI sees it. It uses a set of configurable "rules" – like a checklist – to spot common problematic patterns:

* It can look for specific **keywords or phrases** that often signal trouble (e.g., "ignore your instructions").
* It can spot **unusual formatting or hidden characters** that people use to try and trick AI.
* It can identify queries that are **excessively long or repetitive**.

If QueryGuard finds a problem based on these rules, it can:

* **Block** the message entirely.
* **Flag** the message for review.
* (Planned) Ask the user to **rephrase** their question.

All of this happens very quickly before the main chatbot AI has to do any heavy lifting.

## Who Is QueryGuard For?

* **Chatbot Owners:** If you have a chatbot for your business, project, or community and are facing abuse.
* **Small Businesses:** Protect your customer service or information chatbots.
* **Developers:** QueryGuard is a Python library that developers can integrate into their chatbot applications.

## How Can You Use QueryGuard? (Current Status: Alpha for Developers)

QueryGuard is currently an **alpha-stage software library for Python developers.** This means it's still in active development and is best suited for technical users or for chatbot owners to discuss with their developers.

* **If you are a developer:** You can check out our main `README.md` file for technical details on installation and usage. The project is open-source, and you can find it on GitHub: [https://github.com/IgorWarzocha/QueryGuard](https://github.com/IgorWarzocha/QueryGuard)
* **If you are a chatbot owner (non-technical):** The best approach is to talk to the developer or technical team who built or manages your chatbot. You can show them this page and the main QueryGuard project. They can evaluate if QueryGuard is a good fit for your system and how to integrate it.

While QueryGuard itself is a component that needs to be integrated by a developer, the *principles* behind it – pre-filtering inputs, setting rules, and having a "guard" – are important for any chatbot's health and safety!

## Our Goal

We aim to provide an accessible tool that helps make chatbots safer, more reliable, and more efficient, starting with this important first line of defense.

## For Developers

If you are a developer interested in the technical details of QueryGuard, how to contribute, or the specifics of its implementation, please see our comprehensive **[Developer Guide (DEVELOPERS.md)](DEVELOPERS.md)**.

---
*QueryGuard - Lead Developer: Igor Warzocha*
*Contact: igorwarzocha@gmail.com*
