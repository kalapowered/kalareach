//
//  Runs the application's own native launch code.
//
//  The application's `main` hands the process to Rust, and the windowing library owns the
//  application delegate, so no Swift of this application runs at launch unless something starts
//  it. This registers, before `main` begins, for the system's launch notification and calls the
//  Swift launch code by name when it arrives. It is looked up at run time because a bridging
//  header into the generated project is exactly the hand edit the project generator would
//  overwrite.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

__attribute__((constructor)) static void KRRegisterLaunchHook(void) {
    [[NSNotificationCenter defaultCenter]
        addObserverForName:UIApplicationDidFinishLaunchingNotification
                    object:nil
                     queue:[NSOperationQueue mainQueue]
                usingBlock:^(NSNotification *_Nonnull note) {
                  Class launch = NSClassFromString(@"KRNativeLaunch");
                  SEL entry = NSSelectorFromString(@"didFinishLaunching");
                  if (launch != Nil && [launch respondsToSelector:entry]) {
                      IMP implementation = [launch methodForSelector:entry];
                      ((void (*)(id, SEL))implementation)(launch, entry);
                  }
                }];
}
