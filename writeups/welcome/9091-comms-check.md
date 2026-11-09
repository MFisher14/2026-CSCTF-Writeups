# Comms Check

> Welcome · Welcome · Chronos Security  
> Points: 100 · Flag submitted by: [.dev](https://github.com/d0td3v)

**The flag**

The recognition word is the **#rules** channel topic on the event Discord, prefixed `2026:`. It is channel metadata (not a `CSCTF{...}` value and not a message), visible only to server members, so it is not reproduced here.

**Challenge**

> Comms check. Our net runs on Discord. Fall in with the rest of the fleet and report the recognition word the watch is broadcasting.

No files and no instance.

**Tools used**

A Discord account and client (the desktop or web app).

**Approach / walkthrough**

1. **Rule out the public surfaces first.** Our automated agents had no Discord session, so they checked what is visible without joining: the public server widget (sampled repeatedly for a bot status), the invite preview, and the event site. None of these exposed the word, so the task went to a human team member — the word is members-only channel metadata, so time spent on public surfaces is wasted.

2. **Join the event server.** Use the "Join Discord" link on the event page (`https://www.chronos-security.ro/competitions/csctf-2026`), which points to `discord.gg/GucSYEKvHP`, and accept the invite.

3. **Show all channels.** In the left-hand server list, right-click the server icon and choose **Show All Channels**. Discord's onboarding only lists the channels you opted into, and **#rules** is not one of them by default.

4. **Read the channel topic.** Open **#rules** and view its topic (clicking the topic in the channel header, or right-click → View Channel Details). The recognition word is the channel topic, prefixed `2026:` — it is in the channel's metadata, not posted as a message.

5. **Submit** the value exactly as shown.

**Why it works**

The flag is channel metadata rather than a message: it sits in the #rules topic/description, and #rules is hidden from the default channel list. Only server members can see channel details, so nothing outside the server gives it away — which is the point. It is a sanity check that each team has actually joined the support channel. Chronos has done this before: the 2024 edition hid its rules flag in a channel description too.

**Validation / reproduction**

The value was copied verbatim from the #rules channel topic and accepted on submission. To reproduce: join via the event-page invite, enable Show All Channels, open #rules, and read the topic.
