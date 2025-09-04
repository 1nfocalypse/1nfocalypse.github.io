---
title: "Breaking ThreadLocalRandom in Five Seconds"
math: true
excerpt_separator: "<!--more-->"
categories:
  - Blog
tags:
  - blog
  - PRNGs
  - cryptanalysis
---
The past few days, I took an interest in Java's ThreadLocalRandom implementation while working on a project with [Daeda1usUK](https://github.com/Daeda1usUK). It's a fairly non-standard PRNG marked as not cryptographically secure, but I couldn't find an actual implementation breaking it or even a description of how to do so. So, I wanted to fill that gap, and 
provide a definite bound on security for the generator, particularly given that it can be misused in sensitive contexts.

# Background
### What even is ThreadLocalRandom, and Why Do I Care?
ThreadLocalRandom is Java's means of allowing threading-compatible pseudorandom number generation. This is done such that each thread can have access to its own unique stream of pseudorandom numbers, in turn allowing for more effective parallelization requiring them rather than relying on a single, non-parallelizable stream. However, ThreadLocalRandom doesn't use a 
typical class of PRNG - no MT19937 here, as the state required for MT19937 is obscenely expensive. As such, we have a custom-rolled PRNG that takes design cues from linear congruential generators, counter-based PRNGs (like the ever-so-popular Philox), and hash functions. 
We will largely follow [Alvaro Videla's writeup](https://alvaro-videla.com/2016/10/inside-java-s-threadlocalrandom.html) to explain the what and why behind the PRNG used here, with an emphasis on the `nextInt()` function. If we consult [OpenJDK 8+'s implementation](https://hg.openjdk.org/jdk8/jdk8/jdk/file/687fd7c7986d/src/share/classes/java/util/concurrent/ThreadLocalRandom.java#l366),
we can trace through how this generator actually works. We first define `nextInt()`:
```Java
    /**
     * Returns a pseudorandom {@code int} value.
     *
     * @return a pseudorandom {@code int} value
     */
    public int nextInt() {
        return mix32(nextSeed());
    }
```
Fairly straightforward function, but not entirely informative about what's actually going on here. Let's take a peek into [`nextSeed()`](https://hg.openjdk.org/jdk8/jdk8/jdk/file/687fd7c7986d/src/share/classes/java/util/concurrent/ThreadLocalRandom.java#l268):
```Java
    final long nextSeed() {
        Thread t; long r; // read and update per-thread seed
        UNSAFE.putLong(t = Thread.currentThread(), SEED,
                       r = UNSAFE.getLong(t, SEED) + GAMMA);
        return r;
    }
```
This gives us a bit more of the information we're looking for. Each thread has some 64 bit value as an identifier, which becomes the seed of the PRNG, guaranteeing uniqueness. Then, on each call, this is updated by adding the value GAMMA (`0x9E3779B97F4A7C15`) modulo $2^{64}$. GAMMA, per Videla's writeup, comes from RC5 (Rivest Cipher 5), which in turn is derived 
from the golden ratio as a nothing-up-my-sleeve number. This allows for a maximal period of unique 64 bit outputs, and given that each seed is also unique, provides a strong base point for input into a PRNG. This can be thought of readily as a Linear Congruential Generator with the multiplicand set to $1$, i.e.
$$o_n = (a * o_{n-1} + c) \bmod 2^{64} \rightarrow o_n = (1 * o_{n-1} + 0x9E3779B97F4A7C15_{16}) \bmod 2^{64}$$
We prove maximal period via Hull-Dobell:

- $GCD(2^{64}, 0x9E3779B97F4A7C15_{16})$ == $1$? True
- $a - 1 = 0 \rightarrow 2 \mid 0$
- $a - 1 = 0 \rightarrow 4 \mid 0$

Ok, so they have the right idea for ensuring unique and long-period inputs in a very lightweight manner. While still suffering from Marsaglia's Theorem on the inputs, the structure will be destroyed by [`mix32(long z)`](https://hg.openjdk.org/jdk8/jdk8/jdk/file/687fd7c7986d/src/share/classes/java/util/concurrent/ThreadLocalRandom.java#l210), defined as:
```Java
    private static int mix32(long z) {
        z = (z ^ (z >>> 33)) * 0xff51afd7ed558ccdL;
        return (int)(((z ^ (z >>> 33)) * 0xc4ceb9fe1a85ec53L) >>> 32);
    }
```
This is the method that's actually responsible for the statistical randomness observed in the outputs of ThreadLocalRandom. We get more magic numbers here, but Videla once again explains them as coming from the MurmurHash algorithm. This is the final step that actually modifies the outputs of the PRNG, notably narrowing the type from `long` to `int`.

# Breaking Things
### Randomness Isn't So Random
Naturally, computers struggle with randomness. They're deterministic machines, which conflicts with the concept of randomness. So, we use PRNGs to simulate it, and more often than not, they are judged by their statistical ability to appear how a uniformly random distribution should. Multiple tests exist for this, ranging from ENT (a classic, albeit very limited 
testsuite) to TestU01's BigCrush, an unbelievably stringent test suite and the current industry standard. Once again in reference to Videla's writeup, a similar variant of this algorithm has been put through TestU01 and was determined "adequate for everyday use" (Steele, Lea, Flood; *Fast Splittable Pseudorandom Number Generators*). This algorithm, however, is not 
cryptographically secure, meaning that it can be inverted to find the seed and simulate, either forwards or backwards, the output stream, in an efficient manner, usually with minimal or no assumptions ("black-box inversion"). A counterexample to this would be the implementation of ChaCha20 used by the Linux kernel since 2020 for `/dev/(u)random`, which is 
cryptographically secure. 

### Strategy
We start by stepping backwards through the algorithm. We at first presume that we have only one output - this is the best case for a cryptanalyst. We will call our output $o$. Furthermore, for ease of understanding, we will only consider unsigned integral types. While the actual application uses signed types, it becomes easier to think about with unsigned numbers.

Consider $o$ to be an unsigned, 32 bit number resulting from the pseudocode statement:
```Java
return (u32)(((z ^ (z >> 33)) * 0xc4ceb9fe1a85ec53) >> 32)
```
We can trivially widen the type to be a u64, so we shall do that, giving us $o$ represented as:
```
    0s        N
|--------|--------|
```
We are now considering the statement:
```Java
return ((z ^ (z >> 33)) * 0xc4ceb9fe1a85ec53) >> 32
```
This means that our current 32 bits are actually the high bits of the output - we can just left shift by 32 in order to put them back where they belong with absolute certainty that those were the true 32 high bits resulting from these operations. However, since we lost the 32 low bits completely, we encounter our first bit of actual friction. Since there's not really a means of recovering them, we move on to our next-best strategy: guessing. Since this is only $2^{32}$ guesses, it's still very much within the bounds of computational feasability - we're willing to take that loss. So, we enumerate all $2^{32}$ 32-bit words, and place them as the low bits in our output $o$, forming a set of all possible outputs $N$.
We also note that the magic number `0xC4CEB9FE1A85EC53` is odd, and that operations of 64 bit integers are defined to take place modulo $2^{64}$. This means that this structure is actually an algebraic ring, with the odd values being unitary. This in turn means that, given our magic number is an odd number, it is guaranteed that there exists a multiplicative inverse such that $n * n^{-1} \bmod 2^{64} \equiv 1$. We find said inverse as `0x9CB4B2F8129337DB`. We apply this to all of our guesses, which in turn leaves us with the set of all possible outputs of:
```Java
return (z ^ (z >> 33)
```
We notice here that, since `z` is a 64 bit number, we preserve the top 33 bits of the number with this operation. Given that the XOR operator is its own inverse, and only the 31 low bits are affected by this transformation, we can simply apply it again, also to the low 31 bits, to recover the original value `z`. We then turn our attention to the statement:
```Java
z = (z ^ (z >> 33)) * 0xff51afd7ed558ccd;
```
We observe that, once again, this constant is unitary. We derive the inverse as `0x4F74430C22A54005`, and repeat the previous steps. At this point, we have determined all possible input values to `mix32(long z)` that could map to the output value. If we have an oracle, i.e. some model where we can submit a seed and ask if it is the correct one, we simply try all of the possibile values until we have the correct one, with time complexity $2^{32}$ and a single output required. However, in the case that we do not have such an oracle, we require more outputs to uniquely determine the input value. With two outputs, we expect a single collision, that is, we expect both the real result and a false positive, with no way to decide which one is correct. However, with three outputs, we only expect the true output. We consider the following mechanism for checking validity, given some candidate recovered input $z$ and outputs $o_1, o_2, o_3$:
```py
if mix32(z + GAMMA) == o_2 and mix32(z + 2*GAMMA) == o_3
  return z
```
Since we know the defined constant GAMMA, we simply check that the output of mix32 given our candidate $z$ plus GAMMA produces $o_2$, and to eliminate the collision, we repeat this with $z$ plus $2*\text{GAMMA}$. On return we have correctly deduced the input into `mix32(long z)` for this stream, in turn meaning we have deduced the seed for the thread. Since it is simply governed by the addition of GAMMA, we can add or subtract GAMMA modulo $2^{64}$ to find previous or the next values.

### Implementation Considerations
As described, this has a storage complexity of $2^{32}$ 64 bit numbers, or presuming zero overhead, approximately 34 GB of data. While this is definitely doable on modern consumer systems or clusters, we would prefer to not have this complexity, as it will slow us down and is (as we will come to find out) a waste of resources. We can completely eliminate the need for storing the complete set of possible values by simply guessing a candidate, performing all of the inversion operations on it (as we would have had to do anyways), and evaluating if it meets our earlier constraints. This completely eliminates our storage requirements, denoting that a full recovery can be conducted in $2^{32}$ time complexity with negigible storage complexity. Of additional note, and while not implemented in the below proof of concept, this is also embarassingly parallel, which can offer drastic speedups. The below C++ is a proof of concept whipped up to mimic ThreadLocalRandom, and showcase the inversion.

```cpp
#include <iostream>
#include <cstdint>

const uint64_t GAMMA = 0x9e3779b97f4a7c15;
 
inline uint32_t mix32(uint64_t num)
{
 num = (num ^ (num >> 33)) * 0xff51afd7ed558ccd;
  return static_cast<uint32_t>(((num ^ (num >> 33)) * 0xc4ceb9fe1a85ec53) >> 32);
}
 
int main()
{
  uint64_t threadSeed = 0x1234567812345678;
  uint32_t T1 = mix32(threadSeed + GAMMA);
  uint32_t T2 = mix32(threadSeed + 2*GAMMA);
  uint32_t T3 = mix32(threadSeed + 3*GAMMA);
  uint64_t hi = static_cast<uint64_t>(T1) << 32;
  uint64_t recoveredSeed = 0;
 
  for (size_t i = 0; i < (1ull << 32); ++i)
  {
    uint64_t num2 = hi | static_cast<uint32_t>(i); // concat guess
    num2 *= 0x9cb4b2f8129337db; // unit inverse
    num2 = num2 ^ (num2 >> 33); // de-xor
    num2 *= 0x4f74430c22a54005; // other unit inverse
    num2 = num2 ^ (num2 >> 33); // de-xor again
    
    // double check to prevent collision
    if (mix32(num2 + GAMMA) == T2 && mix32(num2 + 2*GAMMA) == T3)
    {
      recoveredSeed = num2 - GAMMA;
      std::cout << "[+] Recovered seed." << std::endl;
      std::cout << "[*] 0x" << std::hex << recoveredSeed << std::endl;
    }
  }
  std::cout << "Found seed: 0x" << std::hex << recoveredSeed << std::endl;
  return 0;
}
```
This code, compiled with GCC 14.2.1 on Void Linux using the -O3 and -march=native flags, was able to complete in approximately 3.6 seconds on an i9-14900k. Thus, we provide a theoretical bound of time complexity $2^{32}$ to invert the generator, a heuristic benchmark of approximately 3.6 seconds to break, and negligible storage complexity, with single-output inversion possible presuming an oracle and three-output inversion possible without one.

# Conclusion
I hope that you found this useful or insightful! It was a fun exercise and a decidedly interesting generator to work with. Of course, this is your reminder that [CWE-338](https://cwe.mitre.org/data/definitions/338.html) exists, and using this generator in secrecy-sensitive contexts will get you owned. Consider alternatives like Fortuna or ChaCha20 for secure use cases. This is my first blog post, so please provide feedback on what you would like more or less of. I plan to somewhat-regularly post here, so hopefully your feedback will get things better, faster. Thank you for reading!
