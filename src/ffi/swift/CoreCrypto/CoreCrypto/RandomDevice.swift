//
// Created by Aman LaChapelle on 11/2/18.
//

import Foundation

import libCoreCrypto

public class RandomDevice {
  public func getGenerator() -> rng_buf? {
    return nil
  }

  public func getErrGenerator() -> rng_err? {
    return nil
  }

  func getInternal() -> random_device_t {
    return random_device_t(generator: self.getGenerator()!, err: self.getErrGenerator()!)
  }
}

class DefaultRandomDevice: RandomDevice {
  override func getGenerator() -> rng_buf {
    return { bytes, count in
      return SecRandomCopyBytes(kSecRandomDefault, count, bytes!)
    }
  }

  override func getErrGenerator() -> rng_err {
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
