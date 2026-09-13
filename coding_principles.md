TigerStyle
The Essence Of Style
“There are three things extremely hard: steel, a diamond, and to know one's self.” — Benjamin Franklin

TigerBeetle's coding style is evolving. A collective give-and-take at the intersection of engineering and art. Numbers and human intuition. Reason and experience. First principles and knowledge. Precision and poetry. Just like music. A tight beat. A rare groove. Words that rhyme and rhymes that break. Biodigital jazz. This is what we've learned along the way. The best is yet to come.

Why Have Style?
Another word for style is design.

“The design is not just what it looks like and feels like. The design is how it works.” — Steve Jobs

Our design goals are safety, performance, and developer experience. In that order. All three are important. Good style advances these goals. Does the code make for more or less safety, performance or developer experience? That is why we need style.

Put this way, style is more than readability, and readability is table stakes, a means to an end rather than an end in itself.

“...in programming, style is not something to pursue directly. Style is necessary only where understanding is missing.” ─ Let Over Lambda

This document explores how we apply these design goals to coding style. First, a word on simplicity, elegance and technical debt.

On Simplicity And Elegance
Simplicity is not a free pass. It's not in conflict with our design goals. It need not be a concession or a compromise.

Rather, simplicity is how we bring our design goals together, how we identify the “super idea” that solves the axes simultaneously, to achieve something elegant.

“Simplicity and elegance are unpopular because they require hard work and discipline to achieve” — Edsger Dijkstra

Contrary to popular belief, simplicity is also not the first attempt but the hardest revision. It's easy to say “let's do something simple”, but to do that in practice takes thought, multiple passes, many sketches, and still we may have to “throw one away”.

The hardest part, then, is how much thought goes into everything.

We spend this mental energy upfront, proactively rather than reactively, because we know that when the thinking is done, what is spent on the design will be dwarfed by the implementation and testing, and then again by the costs of operation and maintenance.

An hour or day of design is worth weeks or months in production:

“the simple and elegant systems tend to be easier and faster to design and get right, more efficient in execution, and much more reliable” — Edsger Dijkstra

Technical Debt
What could go wrong? What's wrong? Which question would we rather ask? The former, because code, like steel, is less expensive to change while it's hot. A problem solved in production is many times more expensive than a problem solved in implementation, or a problem solved in design.

Since it's hard enough to discover showstoppers, when we do find them, we solve them. We don't allow potential memcpy latency spikes, or exponential complexity algorithms to slip through.

“You shall not pass!” — Gandalf

In other words, TigerBeetle has a “zero technical debt” policy. We do it right the first time. This is important because the second time may not transpire, and because doing good work, that we can be proud of, builds momentum.

We know that what we ship is solid. We may lack crucial features, but what we have meets our design goals. This is the only way to make steady incremental progress, knowing that the progress we have made is indeed progress.

Safety
“The rules act like the seat-belt in your car: initially they are perhaps a little uncomfortable, but after a while their use becomes second-nature and not using them becomes unimaginable.” — Gerard J. Holzmann

NASA's Power of Ten — Rules for Developing Safety Critical Code will change the way you code forever. To expand:

Use only very simple, explicit control flow for clarity. Do not use recursion to ensure that all executions that should be bounded are bounded. Use only a minimum of excellent abstractions but only if they make the best sense of the domain. Abstractions are never zero cost. Every abstraction introduces the risk of a leaky abstraction.

Put a limit on everything because, in reality, this is what we expect—everything has a limit. For example, all loops and all queues must have a fixed upper bound to prevent infinite loops or tail latency spikes. This follows the “fail-fast” principle so that violations are detected sooner rather than later. Where a loop cannot terminate (e.g. an event loop), this must be asserted.

Use explicitly-sized types like u32 for everything, avoid architecture-specific usize.

Assertions detect programmer errors. Unlike operating errors, which are expected and which must be handled, assertion failures are unexpected. The only correct way to handle corrupt code is to crash. Assertions downgrade catastrophic correctness bugs into liveness bugs. Assertions are a force multiplier for discovering bugs by fuzzing.

Assert all function arguments and return values, pre/postconditions and invariants. A function must not operate blindly on data it has not checked. The purpose of a function is to increase the probability that a program is correct. Assertions within a function are part of how functions serve this purpose. The assertion density of the code must average a minimum of two assertions per function.

Pair assertions. For every property you want to enforce, try to find at least two different code paths where an assertion can be added. For example, assert validity of data right before writing it to disk, and also immediately after reading from disk.

On occasion, you may use a blatantly true assertion instead of a comment as stronger documentation where the assertion condition is critical and surprising.

Split compound assertions: prefer assert(a); assert(b); over assert(a and b);. The former is simpler to read, and provides more precise information if the condition fails.

Use single-line if to assert an implication: if (a) assert(b).

Assert the relationships of compile-time constants as a sanity check, and also to document and enforce subtle invariants or type sizes. Compile-time assertions are extremely powerful because they are able to check a program's design integrity before the program even executes.

The golden rule of assertions is to assert the positive space that you do expect AND to assert the negative space that you do not expect because where data moves across the valid/invalid boundary between these spaces is where interesting bugs are often found. This is also why tests must test exhaustively, not only with valid data but also with invalid data, and as valid data becomes invalid.

Assertions are a safety net, not a substitute for human understanding. With simulation testing, there is the temptation to trust the fuzzer. But a fuzzer can prove only the presence of bugs, not their absence. Therefore:

Build a precise mental model of the code first,
encode your understanding in the form of assertions,
write the code and comments to explain and justify the mental model to your reviewer,
and use VOPR as the final line of defense, to find bugs in your and reviewer's understanding of code.
All memory must be statically allocated at startup. No memory may be dynamically allocated (or freed and reallocated) after initialization. This avoids unpredictable behavior that can significantly affect performance, and avoids use-after-free. As a second-order effect, it is our experience that this also makes for more efficient, simpler designs that are more performant and easier to maintain and reason about, compared to designs that do not consider all possible memory usage patterns upfront as part of the design.

Declare variables at the smallest possible scope, and minimize the number of variables in scope, to reduce the probability that variables are misused.

There's a sharp discontinuity between a function fitting on a screen, and having to scroll to see how long it is. For this physical reason we enforce a hard limit of 70 lines per function. Art is born of constraints. There are many ways to cut a wall of code into chunks of 70 lines, but only a few splits will feel right. Some rules of thumb:

Good function shape is often the inverse of an hourglass: a few parameters, a simple return type, and a lot of meaty logic between the braces.
Centralize control flow. When splitting a large function, try to keep all switch/if statements in the "parent" function, and move non-branchy logic fragments to helper functions. Divide responsibility. All control flow should be handled by one function, the rest shouldn't care about control flow at all. In other words, "push ifs up and fors down".
Similarly, centralize state manipulation. Let the parent function keep all relevant state in local variables, and use helpers to compute what needs to change, rather than applying the change directly. Keep leaf functions pure.
Appreciate, from day one, all compiler warnings at the compiler's strictest setting.

Whenever your program has to interact with external entities, don't do things directly in reaction to external events. Instead, your program should run at its own pace. Not only does this make your program safer by keeping the control flow of your program under your control, it also improves performance for the same reason (you get to batch, instead of context switching on every event). Additionally, this makes it easier to maintain bounds on work done per time period.

Beyond these rules:

Compound conditions that evaluate multiple booleans make it difficult for the reader to verify that all cases are handled. Split compound conditions into simple conditions using nested if/else branches. Split complex else if chains into else { if { } } trees. This makes the branches and cases clear. Again, consider whether a single if does not also need a matching else branch, to ensure that the positive and negative spaces are handled or asserted.

Negations are not easy! State invariants positively. When working with lengths and indexes, this form is easy to get right (and understand):

if (index < count) {
  // The invariant holds.
} else {
  // The invariant doesn't hold.
}
This form is harder, and also goes against the grain of how index would typically be compared to count, for example, in a loop condition:

if (index >= count) {
  // It's not true that the invariant holds.
}
All errors must be handled. An analysis of production failures in distributed data-intensive systems found that the majority of catastrophic failures could have been prevented by simple testing of error handling code.

“Specifically, we found that almost all (92%) of the catastrophic system failures are the result of incorrect handling of non-fatal errors explicitly signaled in software.”

Always motivate, always say why. Never forget to say why. Because if you explain the rationale for a decision, it not only increases the hearer's understanding, and makes them more likely to adhere or comply, but it also shares criteria with them with which to evaluate the decision and its importance.

Explicitly pass options to library functions at the call site, instead of relying on the defaults. For example, write @prefetch(a, .{ .cache = .data, .rw = .read, .locality = 3 }); over @prefetch(a, .{});. This improves readability but most of all avoids latent, potentially catastrophic bugs in case the library ever changes its defaults.

Performance
“The lack of back-of-the-envelope performance sketches is the root of all evil.” — Rivacindela Hudsoni

Think about performance from the outset, from the beginning. The best time to solve performance, to get the huge 1000x wins, is in the design phase, which is precisely when we can't measure or profile. It's also typically harder to fix a system after implementation and profiling, and the gains are less. So you have to have mechanical sympathy. Like a carpenter, work with the grain.

Perform back-of-the-envelope sketches with respect to the four resources (network, disk, memory, CPU) and their two main characteristics (bandwidth, latency). Sketches are cheap. Use sketches to be “roughly right” and land within 90% of the global maximum.

Optimize for the slowest resources first (network, disk, memory, CPU) in that order, after compensating for the frequency of usage, because faster resources may be used many times more. For example, a memory cache miss may be as expensive as a disk fsync, if it happens many times more.

Distinguish between the control plane and data plane. A clear delineation between control plane and data plane through the use of batching enables a high level of assertion safety without losing performance. See our July 2021 talk on Zig SHOWTIME for examples.

Amortize network, disk, memory and CPU costs by batching accesses.

Let the CPU be a sprinter doing the 100m. Be predictable. Don't force the CPU to zig zag and change lanes. Give the CPU large enough chunks of work. This comes back to batching.

Be explicit. Minimize dependence on the compiler to do the right thing for you.

In particular, extract hot loops into stand-alone functions with primitive arguments without self (see an example). That way, the compiler doesn't need to prove that it can cache struct's fields in registers, and a human reader can spot redundant computations easier.

Developer Experience
“There are only two hard things in Computer Science: cache invalidation, naming things, and off-by-one errors.” — Phil Karlton

Naming Things
Get the nouns and verbs just right. Great names are the essence of great code, they capture what a thing is or does, and provide a crisp, intuitive mental model. They show that you understand the domain. Take time to find the perfect name, to find nouns and verbs that work together, so that the whole is greater than the sum of its parts.

Use snake_case for function, variable, and file names. The underscore is the closest thing we have as programmers to a space, and helps to separate words and encourage descriptive names. We don't use Zig's CamelCase.zig style for "struct" files to keep the convention simple and consistent.

Do not abbreviate variable names, unless the variable is a primitive integer type used as an argument to a sort function or matrix calculation. Use long form arguments in scripts: --force, not -f. Single letter flags are for interactive usage.

Use proper capitalization for acronyms (VSRState, not VsrState).

For the rest, follow the Zig style guide.

Add units or qualifiers to variable names, and put the units or qualifiers last, sorted by descending significance, so that the variable starts with the most significant word, and ends with the least significant word. For example, latency_ms_max rather than max_latency_ms. This will then line up nicely when latency_ms_min is added, as well as group all variables that relate to latency.

Infuse names with meaning. For example, allocator: Allocator is a good, if boring name, but gpa: Allocator and arena: Allocator are excellent. They inform the reader whether deinit should be called explicitly.

When choosing related names, try hard to find names with the same number of characters so that related variables all line up in the source. For example, as arguments to a memcpy function, source and target are better than src and dest because they have the second-order effect that any related variables such as source_offset and target_offset will all line up in calculations and slices. This makes the code symmetrical, with clean blocks that are easier for the eye to parse and for the reader to check.

When a single function calls out to a helper function or callback, prefix the name of the helper function with the name of the calling function to show the call history. For example, read_sector() and read_sector_callback().

Callbacks go last in the list of parameters. This mirrors control flow: callbacks are also invoked last.

Order matters for readability (even if it doesn't affect semantics). On the first read, a file is read top-down, so put important things near the top. The main function goes first.

The same goes for structs, the order is fields then types then methods:

time: Time,
process_id: ProcessID,

const ProcessID = struct { cluster: u128, replica: u8 };
const Tracer = @This(); // This alias concludes the types section.

pub fn init(gpa: std.mem.Allocator, time: Time) !Tracer {
    ...
}
If a nested type is complex, make it a top-level struct.

At the same time, not everything has a single right order. When in doubt, consider sorting alphabetically, taking advantage of big-endian naming.

Don't overload names with multiple meanings that are context-dependent. For example, TigerBeetle has a feature called pending transfers where a pending transfer can be subsequently posted or voided. At first, we called them two-phase commit transfers, but this overloaded the two-phase commit terminology that was used in our consensus protocol, causing confusion.

Think of how names will be used outside the code, in documentation or communication. For example, a noun is often a better descriptor than an adjective or present participle, because a noun can be directly used in correspondence without having to be rephrased. Compare replica.pipeline vs replica.preparing. The former can be used directly as a section header in a document or conversation, whereas the latter must be clarified. Noun names compose more clearly for derived identifiers, e.g. config.pipeline_max.

Zig has named arguments through the options: struct pattern. Use it when arguments can be mixed up. A function taking two u64 must use an options struct. If an argument can be null, it should be named so that the meaning of null literal at the call site is clear.

Because dependencies like an allocator or a tracer are singletons with unique types, they should be threaded through constructors positionally, from the most general to the most specific.

Write descriptive commit messages that inform and delight the reader, because your commit messages are being read. Note that a pull request description is not stored in the git repository and is invisible in git blame, and therefore is not a replacement for a commit message.

Don't forget to say why. Code alone is not documentation. Use comments to explain why you wrote the code the way you did. Show your workings.

Don't forget to say how. For example, when writing a test, think of writing a description at the top to explain the goal and methodology of the test, to help your reader get up to speed, or to skip over sections, without forcing them to dive in.

Comments are sentences, with a space after the slash, with a capital letter and a full stop, or a colon if they relate to something that follows. Comments are well-written prose describing the code, not just scribblings in the margin. Comments after the end of a line can be phrases, with no punctuation.

Cache Invalidation
Don't duplicate variables or take aliases to them. This will reduce the probability that state gets out of sync.

If you don't mean a function argument to be copied when passed by value, and if the argument type is more than 16 bytes, then pass the argument as *const. This will catch bugs where the caller makes an accidental copy on the stack before calling the function.

Construct larger structs in-place by passing an out pointer during initialization.

In-place initializations can assume pointer stability and immovable types while eliminating intermediate copy-move allocations, which can lead to undesirable stack growth.

Keep in mind that in-place initializations are viral — if any field is initialized in-place, the entire container struct should be initialized in-place as well.

Prefer:

fn init(target: *LargeStruct) !void {
  target.* = .{
    // in-place initialization.
  };
}

fn main() !void {
  var target: LargeStruct = undefined;
  try target.init();
}
Over:

fn init() !LargeStruct {
  return LargeStruct {
    // moving the initialized object.
  }
}

fn main() !void {
  var target = try LargeStruct.init();
}
Shrink the scope to minimize the number of variables at play and reduce the probability that the wrong variable is used.

Calculate or check variables close to where/when they are used. Don't introduce variables before they are needed. Don't leave them around where they are not. This will reduce the probability of a POCPOU (place-of-check to place-of-use), a distant cousin to the infamous TOCTOU. Most bugs come down to a semantic gap, caused by a gap in time or space, because it's harder to check code that's not contained along those dimensions.

Use simpler function signatures and return types to reduce dimensionality at the call site, the number of branches that need to be handled at the call site, because this dimensionality can also be viral, propagating through the call chain. For example, as a return type, void trumps bool, bool trumps u64, u64 trumps ?u64, and ?u64 trumps !u64.

Ensure that functions run to completion without suspending, so that precondition assertions are true throughout the lifetime of the function. These assertions are useful documentation without a suspend, but may be misleading otherwise.

Be on your guard for buffer bleeds. This is a buffer underflow, the opposite of a buffer overflow, where a buffer is not fully utilized, with padding not zeroed correctly. This may not only leak sensitive information, but may cause deterministic guarantees as required by TigerBeetle to be violated.

Use newlines to group resource allocation and deallocation, i.e. before the resource allocation and after the corresponding defer statement, to make leaks easier to spot.

Off-By-One Errors
The usual suspects for off-by-one errors are casual interactions between an index, a count or a size. These are all primitive integer types, but should be seen as distinct types, with clear rules to cast between them. To go from an index to a count you need to add one, since indexes are 0-based but counts are 1-based. To go from a count to a size you need to multiply by the unit. Again, this is why including units and qualifiers in variable names is important.

Show your intent with respect to division. For example, use @divExact(), @divFloor() or div_ceil() to show the reader you've thought through all the interesting scenarios where rounding may be involved.

Style By The Numbers
Run zig fmt.

Use 4 spaces of indentation, rather than 2 spaces, as that is more obvious to the eye at a distance.

Hard limit all line lengths, without exception, to at most 100 columns for a good typographic "measure". Use it up. Never go beyond. Nothing should be hidden by a horizontal scrollbar. Let your editor help you by setting a column ruler. To wrap a function signature, call or data structure, add a trailing comma, close your eyes and let zig fmt do the rest.

Similar to function length, the motivation behind the number 100 is physical: just enough to fit two copies of the code side-by-side on a screen.

Add braces to the if statement unless it fits on a single line for consistency and defense in depth against "goto fail;" bugs.

Dependencies
TigerBeetle has a “zero dependencies” policy, apart from the Zig toolchain. Dependencies, in general, inevitably lead to supply chain attacks, safety and performance risk, and slow install times. For foundational infrastructure in particular, the cost of any dependency is further amplified throughout the rest of the stack.

Tooling
Similarly, tools have costs. A small standardized toolbox is simpler to operate than an array of specialized instruments each with a dedicated manual. Our primary tool is Zig. It may not be the best for everything, but it's good enough for most things. We invest into our Zig tooling to ensure that we can tackle new problems quickly, with a minimum of accidental complexity in our local development environment.

“The right tool for the job is often the tool you are already using—adding new tools has a higher cost than many people appreciate” — John Carmack

For example, the next time you write a script, instead of scripts/*.sh, write scripts/*.zig.

This not only makes your script cross-platform and portable, but introduces type safety and increases the probability that running your script will succeed for everyone on the team, instead of hitting a Bash/Shell/OS-specific issue.

Standardizing on Zig for tooling is important to ensure that we reduce dimensionality, as the team, and therefore the range of personal tastes, grows. This may be slower for you in the short term, but makes for more velocity for the team in the long term.

Most serious software development projects use coding guidelines. These guidelines are
meant to state what the ground rules are for the software to be written: how it should be
structured and which language features should and should not be used. Curiously, there is
little consensus on what a good coding standard is. Among the many that have been
written there are remarkable few patterns to discern, except that each new document
tends to be longer than the one before it. The result is that most existing guidelines
contain well over a hundred rules, sometimes with questionable justification. Some rules,
especially those that try to stipulate the use of white-space in programs, may have been
introduced by personal preference; others are meant to prevent very specific and unlikely
types of error from earlier coding efforts within the same organization. Not surprisingly,
the existing coding guidelines tend to have little effect on what developers actually do
when they write code. The most dooming aspect of many of the guidelines is that they
rarely allow for comprehensive tool-based compliance checks. Tool-based checks are
important, since it is often infeasible to manually review the hundreds of thousands of
lines of code that are written for larger applications.
The benefit of existing coding guidelines is therefore often small, even for critical
applications. A verifiable set of well-chosen coding rules could, however, make critical
software components more thoroughly analyzable, for properties that go beyond
compliance with the set of rules itself. To be effective, though, the set of rules has to be
small, and must be clear enough that it can easily be understood and remembered. The
rules will have to be specific enough that they can be checked mechanically. To put an
easy upper-bound on the number of rules for an effective guideline, I will argue that we
can get significant benefit by restricting to no more than ten rules. Such a small set, of
course, cannot be all-encompassing, but it can give us a foothold to achieve measurable
effects on software reliability and verifiability. To support strong checking, the rules are
somewhat strict – one might even say Draconian. The trade-off, though, should be clear.
When it really counts, especially in the development of safety critical code, it may be
worth going the extra mile and living within stricter limits than may be desirable. In
return, we should be able to demonstrate more convincingly that critical software will
work as intended.
Ten Rules for Safety Critical Coding
The choice of language for a safety critical code is in itself a key consideration, but we
will not debate it much here. At many organizations, JPL included, critical code is written
in C. With its long history, there is extensive tool support for this language, including
1 The research described in this paper was carried out at the Jet Propulsion Laboratory, California Institute
of Technology, under a contract with the National Aeronautics and Space Administration.
strong source code analyzers, logic model extractors, metrics tools, debuggers, test
support tools, and a choice of mature, stable compilers. For this reason, C is also the
target of the majority of coding guidelines that have been developed. For fairly pragmatic
reasons, then, our coding rules primarily target C and attempt to optimize our ability to
more thoroughly check the reliability of critical applications written in C.
The following rules may provide benefit, especially if the low number means that
developers will actually adhere to them. Each rule is followed with a brief rationale for its
inclusion.
1. Rule: Restrict all code to very simple control flow constructs – do not use goto
statements, setjmp or longjmp constructs, and direct or indirect recursion.
Rationale: Simpler control flow translates into stronger capabilities for verification
and often results in improved code clarity. The banishment of recursion is perhaps the
biggest surprise here. Without recursion, though, we are guaranteed to have an
acyclic function call graph, which can be exploited by code analyzers, and can
directly help to prove that all executions that should be bounded are in fact bounded.
(Note that this rule does not require that all functions have a single point of return –
although this often also simplifies control flow. There are enough cases, though,
where an early error return is the simpler solution.)
2. Rule: All loops must have a fixed upper-bound. It must be trivially possible for a
checking tool to prove statically that a preset upper-bound on the number of iterations
of a loop cannot be exceeded. If the loop-bound cannot be proven statically, the rule
is considered violated.
Rationale: The absence of recursion and the presence of loop bounds prevents
runaway code. This rule does not, of course, apply to iterations that are meant to be
non-terminating (e.g., in a process scheduler). In those special cases, the reverse rule
is applied: it should be statically provable that the iteration cannot terminate.
One way to support the rule is to add an explicit upper-bound to all loops that have a
variable number of iterations (e.g., code that traverses a linked list). When the upperbound is exceeded an assertion failure is triggered, and the function containing the
failing iteration returns an error. (See Rule 5 about the use of assertions.)
3. Rule: Do not use dynamic memory allocation after initialization.
Rationale: This rule is common for safety critical software and appears in most
coding guidelines. The reason is simple: memory allocators, such as malloc, and
garbage collectors often have unpredictable behavior that can significantly impact
performance. A notable class of coding errors also stems from mishandling of
memory allocation and free routines: forgetting to free memory or continuing to use
memory after it was freed, attempting to allocate more memory than physically
available, overstepping boundaries on allocated memory, etc. Forcing all applications
to live within a fixed, pre-allocated, area of memory can eliminate many of these
problems and make it easier to verify memory use. Note that the only way to
dynamically claim memory in the absence of memory allocation from the heap is to
use stack memory. In the absence of recursion (Rule 1), an upper-bound on the use of
stack memory can derived statically, thus making it possible to prove that an
application will always live within its pre-allocated memory means.
4. Rule: No function should be longer than what can be printed on a single sheet of
paper in a standard reference format with one line per statement and one line per
declaration. Typically, this means no more than about 60 lines of code per function.
Rationale: Each function should be a logical unit in the code that is understandable
and verifiable as a unit. It is much harder to understand a logical unit that spans
multiple screens on a computer display or multiple pages when printed. Excessively
long functions are often a sign of poorly structured code.
5. Rule: The assertion density of the code should average to a minimum of two
assertions per function. Assertions are used to check for anomalous conditions that
should never happen in real-life executions. Assertions must always be side-effect
free and should be defined as Boolean tests. When an assertion fails, an explicit
recovery action must be taken, e.g., by returning an error condition to the caller of the
function that executes the failing assertion. Any assertion for which a static checking
tool can prove that it can never fail or never hold violates this rule. (I.e., it is not
possible to satisfy the rule by adding unhelpful “assert(true)” statements.)
Rationale: Statistics for industrial coding efforts indicate that unit tests often find at
least one defect per 10 to 100 lines of code written. The odds of intercepting defects
increase with assertion density. Use of assertions is often also recommended as part
of a strong defensive coding strategy. Assertions can be used to verify pre- and postconditions of functions, parameter values, return values of functions, and loopinvariants. Because assertions are side-effect free, they can be selectively disabled
after testing in performance-critical code.
A typical use of an assertion would be as follows:
if (!c_assert(p >= 0) == true) {
return ERROR;
}
with the assertion defined as follows:
#define c_assert(e) ((e) ? (true) : \
(tst_debugging(”%s,%d: assertion ’%s’ failed\n”, \
__FILE__, __LINE__, #e), false))
In this definition, __FILE__ and __LINE__ are predefined by the macro preprocessor
to produce the filename and line-number of the failing assertion. The syntax #e turns
the assertion condition e into a string that is printed as part of the error message. In
code destined for an embedded processor there is of course no place to print the error
message itself – in that case, the call to tst_debugging is turned into a no-op, and
the assertion turns into a pure Boolean test that enables error recovery from
anomolous behavior.
6. Rule: Data objects must be declared at the smallest possible level of scope.
Rationale: This rule supports a basic principle of data-hiding. Clearly if an object is
not in scope, its value cannot be referenced or corrupted. Similarly, if an erroneous
value of an object has to be diagnosed, the fewer the number of statements where the
value could have been assigned; the easier it is to diagnose the problem. The rule
discourages the re-use of variables for multiple, incompatible purposes, which can
complicate fault diagnosis.
7. Rule: The return value of non-void functions must be checked by each calling
function, and the validity of parameters must be checked inside each function.
Rationale: This is possibly the most frequently violated rule, and therefore somewhat
more suspect as a general rule. In its strictest form, this rule means that even the
return value of printf statements and file close statements must be checked. One can
make a case, though, that if the response to an error would rightfully be no different
than the response to success, there is little point in explicitly checking a return value.
This is often the case with calls to printf and close. In cases like these, it can be
acceptable to explicitly cast the function return value to (void) – thereby indicating
that the programmer explicitly and not accidentally decides to ignore a return value.
In more dubious cases, a comment should be present to explain why a return value is
irrelevant. In most cases, though, the return value of a function should not be ignored,
especially if error return values must be propagated up the function call chain.
Standard libraries famously violate this rule with potentially grave consequences. See,
for instance, what happens if you accidentally execute strlen(0), or strcat(s1, s2, -1)
with the standard C string library – it is not pretty. By keeping the general rule, we
make sure that exceptions must be justified, with mechanical checkers flagging
violations. Often, it will be easier to comply with the rule than to explain why noncompliance might be acceptable.
8. Rule: The use of the preprocessor must be limited to the inclusion of header files and
simple macro definitions. Token pasting, variable argument lists (ellipses), and
recursive macro calls are not allowed. All macros must expand into complete
syntactic units. The use of conditional compilation directives is often also dubious,
but cannot always be avoided. This means that there should rarely be justification for
more than one or two conditional compilation directives even in large software
development efforts, beyond the standard boilerplate that avoids multiple inclusion of
the same header file. Each such use should be flagged by a tool-based checker and
justified in the code.
Rationale: The C preprocessor is a powerful obfuscation tool that can destroy code
clarity and befuddle many text based checkers. The effect of constructs in unrestricted
preprocessor code can be extremely hard to decipher, even with a formal language
definition in hand. In a new implementation of the C preprocessor, developers often
have to resort to using earlier implementations as the referee for interpreting complex
defining language in the C standard. The rationale for the caution against conditional
compilation is equally important. Note that with just ten conditional compilation
directives, there could be up to 210 possible versions of the code, each of which would
have to be tested– causing a huge increase in the required test effort.
9. Rule: The use of pointers should be restricted. Specifically, no more than one level of
dereferencing is allowed. Pointer dereference operations may not be hidden in macro
definitions or inside typedef declarations. Function pointers are not permitted.
Rationale: Pointers are easily misused, even by experienced programmers. They can
make it hard to follow or analyze the flow of data in a program, especially by toolbased static analyzers. Function pointers, similarly, can seriously restrict the types of
checks that can be performed by static analyzers and should only be used if there is a
strong justification for their use, and ideally alternate means are provided to assist
tool-based checkers determine flow of control and function call hierarchies. For
instance, if function pointers are used, it can become impossible for a tool to prove
absence of recursion, so alternate guarantees would have to be provided to make up
for this loss in analytical capabilities.
10. Rule: All code must be compiled, from the first day of development, with all
compiler warnings enabled at the compiler’s most pedantic setting. All code must
compile with these setting without any warnings. All code must be checked daily with
at least one, but preferably more than one, state-of-the-art static source code analyzer
and should pass the analyses with zero warnings.
Rationale: There are several very effective static source code analyzers on the
market today, and quite a few freeware tools as well.2 There simply is no excuse for
any software development effort not to make use of this readily available technology.
It should be considered routine practice, even for non-critical code development.
The rule of zero warnings applies even in cases where the compiler or the static
analyzer gives an erroneous warning: if the compiler or the static analyzer gets
confused, the code causing the confusion should be rewritten so that it becomes more
trivially valid. Many developers have been caught in the assumption that a warning
was surely invalid, only to realize much later that the message was in fact valid for
less obvious reasons. Static analyzers have somewhat of a bad reputation due to early
predecessors, such as lint, that produced mostly invalid messages, but this is no
longer the case. The best static analyzers today are fast, and they produce selective
and accurate messages. Their use should not be negotiable at any serious software
project.
The first two rules guarantee the creation of a clear and transparent control flow structure
that is easier to build, test, and analyze. The absence of dynamic memory allocation,
2 For an overview see, for instance, http://spinroot.com/static/index.html
stipulated by the third rule, eliminates a class of problems related to the allocation and
freeing of memory, the use of stray pointers, etc. The next few rules (4 to 7) are fairly
broadly accepted as standards for good coding style. Some benefits of other coding styles
that have been advanced for safety critical systems, e.g., the discipline of “design by
contract” can partly be found in rules 5 to 7.
These ten rules are being used experimentally at JPL in the writing of mission critical
software, with encouraging results. After overcoming a healthy initial reluctance to live
within such strict confines, developers often find that compliance with the rules does tend
to benefit code clarity, analyzability, and code safety. The rules lessen the burden on the
developer and tester to establish key properties of the code (e.g., termination or
boundedness, safe use of memory and stack, etc.) by other means. If the rules seem
Draconian at first, bear in mind that they are meant to make it possible to check code
where very literally your life may depend on its correctness: code that is used to control
the airplane that you fly on, the nuclear power plant a few miles from where you live, or
the spacecraft that carries astronauts into orbit. The rules act like the seat-belt in your car:
initially they are perhaps a little uncomfortable, but after a while their use becomes
second-nature and not using them becomes unimaginable.