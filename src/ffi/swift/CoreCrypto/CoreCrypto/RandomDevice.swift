//
// Created by Aman LaChapelle on 11/2/18.
//

import Foundation

import libCoreCrypto

public typealias RNGBuf = rng_buf
public typealias RNGErr = rng_err

/**
 Peacemakr's cryptography relies on strong random number generation
 to work. We strongly recommend subclassing this interface with a call
 to the Apple-provided SecRandom* APIs.
 */
open class RandomDevice {
  public init() {}

  /**
   Returns the generator associated with this object - a generator
   fills a buffer with a specified number of random bytes.
   */
  open var generator: RNGBuf? {
    return nil
  }

  /**
   Returns the error handler associated with this object - if the
   generator returns nonzero, the library will call this on the return
   code to provide input as to what failed.
   */
  open var err: RNGErr? {
    return nil
  }

  func getInternal() -> random_device_t {
    return random_device_t(generator: self.generator!, err: self.err!)
  }
}

final class DefaultRandomDevice: RandomDevice {

  override var generator: RNGBuf {
    return { bytes, count in
      return SecRandomCopyBytes(kSecRandomDefault, count, bytes!)
    }
  }

  override var err: RNGErr {
    return { code in
        switch code {
        case 0:
            return UnsafePointer("OK")
        default:
            return UnsafePointer("unknown error")
        }
    }
  }

}
