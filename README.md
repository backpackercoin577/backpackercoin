Backpackercoin Core integration/staging tree
=====================================

https://backpackercoin.com

What is Backpackercoin?
----------------

Backpackercoin is an experimental digital asset currency that enables instantly transfer digital asset as 
payments to anyone, anywhere in the world. Backpackercoin uses peer-to-peer technology to operate
with no central authority: managing transactions and issuing money are carried
out collectively by the network. Backpackercoin Core is the name of open source
software which enables the use of this currency.

Backpackercoin Core is built on top of Bitcoin Core. The difference between the two
is the consensus algorithm: Backpackercoin Core uses both Proof of Stake and Proof of Work consensus, 
whilst Bitcoin Core uses Proof of Work. Using Proof of Stake as a consensus algorithm is
allowing it not only to scale better and be orders of magnitude more efficient in
terms of power consumption, but it is also lowering the entry barrier for contributing
to the creation of new blocks.

For more information, as well as an immediately usable, binary version of
the Backpackercoin Core software, see https://www.backpackercoin.com/#wallet-bps, or read the
[original whitepaper](https://www.backpackercoin.com/WhitePaperBPC.pdf).

License
-------

Backpackercoin Core is released under the terms of the MIT license. See [COPYING](COPYING) for more
information or see https://opensource.org/licenses/MIT.

Development Process
-------------------

The `master` branch is regularly built and tested, but is not guaranteed to be
completely stable. [Tags](https://github.com/BPCLAB/backpackercoin/tags) are created
regularly to indicate new official, stable release versions of Backpackercoin Core.

The contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md)
and useful hints for developers can be found in [doc/developer-notes.md](doc/developer-notes.md).

Testing
-------

Testing and code review is the bottleneck for development; we get more pull
requests than we can review and test on short notice. Please be patient and help out by testing
other people's pull requests, and remember this is a security-critical project where any mistake might cost people
lots of money.

### Automated Testing

Developers are strongly encouraged to write [unit tests](src/test/README.md) for new code, and to
submit new unit tests for old code. Unit tests can be compiled and run
(assuming they weren't disabled in configure) with: `make check`. Further details on running
and extending unit tests can be found in [/src/test/README.md](/src/test/README.md).

There are also [regression and integration tests](/test), written
in Python, that are run automatically on the build server.
These tests can be run (if the [test dependencies](/test) are installed) with: `test/functional/test_runner.py`

The Travis CI system makes sure that every pull request is built for Windows, Linux, and macOS, and that unit/sanity tests are run automatically.

### Manual Quality Assurance (QA) Testing

Changes should be tested by somebody other than the developer who wrote the
code. This is especially important for large or high-risk changes. It is useful
to add a test plan to the pull request description if testing the changes is
not straightforward.
