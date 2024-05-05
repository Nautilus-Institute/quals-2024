# amib

## Challenge Type

Reversing

## Difficulty Level

Easy/Medium

## Challenge description

First Flag:

```
Introducing Amib 2000: The Ultimate Text Editing Solution!

Unlock your productivity with Amib 2000, the text editor designed for enthusiasts and professionals alike!
Whether you're coding, crafting reports, or jotting down your next big idea, Amib 2000 offers unparalleled features at an unbeatable price.

Special Offer: Only $50 per User per Machine - Offer Ends 5/6!

Key Features:

    Advanced Editing Tools: Streamline your workflow with customizable syntax highlighting, text manipulation tools, and multiple document interfaces.
    User-Friendly Interface: Enjoy a clean, intuitive interface that lets you focus on your writing without the clutter.
    Compatibility and Support: Works seamlessly on all Windows platforms. Reliable support with regular updates keeps your software on the cutting edge.

Don't miss out on the efficiency and simplicity of Amib 2000.

There is an Easter egg in this new version that is just released. Try your luck and find the egg, ideally in the dark!
```


Second Flag:

```
Introducing Amib 2000: The Ultimate Text Editing Solution!

Unlock your productivity with Amib 2000, the text editor designed for enthusiasts and professionals alike!
Whether you're coding, crafting reports, or jotting down your next big idea, Amib 2000 offers unparalleled features at an unbeatable price.

Special Offer: Only $50 per User per Machine - Offer Ends 5/6!

Key Features:

    Advanced Editing Tools: Streamline your workflow with customizable syntax highlighting, text manipulation tools, and multiple document interfaces.
    User-Friendly Interface: Enjoy a clean, intuitive interface that lets you focus on your writing without the clutter.
    Compatibility and Support: Works seamlessly on all Windows platforms. Reliable support with regular updates keeps your software on the cutting edge.

Don't miss out on the efficiency and simplicity of Amib 2000.
Elevate your text editing experience now for just $50 — this special pricing is only available until May 6th!

Register Amib 2000 today and experience its unique power!
```

## Design

This challenge mimics dumb shareware registration mechanisms from early-2000s.

- `amib` implements a registration key checker.
- The program generates a machine code based on the "name of the motherboard" (who knows what that means).
- The user provides a user name.
- The registration key satisfies the following equation: `decrypt(reg_key) == MD5(username + "|" + machinecode)`.
- The challenge will send all information to our server for verification, and once verification succeeds, the server sends down some binary code that is unencrypted.
- The challenge decrypts the binary code and runs it, which will extract the second flag on the stack.
- How about the first flag? If the user fails registration for 4096 times, the challenge will check if the registration key equals the first flag, which is encoded as the result of a "Lights Out" game.

## Anti-debugging & obfuscation

The only obfuscation exists is that we construct some strings in memory. Really stupid.

## Flags

First flag: `flag{warm_up_with_an_EASY_rev_GXTYjrUY6YRueRW7FOMF}`

Second flag: `flag{HpxULe0jdmc?t=705_3QzfrWsnRU3WKMfk}`

R.I.P. @quend.
