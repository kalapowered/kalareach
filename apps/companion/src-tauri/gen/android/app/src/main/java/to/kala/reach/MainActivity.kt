package to.kala.reach

import android.os.Build
import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import androidx.core.graphics.Insets
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

class MainActivity : TauriActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
    // The web view draws behind the system bars and the display cutout, and how much of that a
    // page hears about depends on the web view's version: an older one reports no inset for the
    // navigation bar, so the gesture handle or the navigation buttons sit over the tab bar, and one
    // that ends short of the window's edge stops reporting the cutout. The content is padded by
    // them instead, so the page ends where they begin whatever the web view is, and they are not
    // reported again to a page that would pad for them a second time. The keyboard is not one of
    // them and is left as it was.
    ViewCompat.setOnApplyWindowInsetsListener(findViewById(android.R.id.content)) { content, insets ->
      val edges = WindowInsetsCompat.Type.statusBars() or
        WindowInsetsCompat.Type.navigationBars() or
        WindowInsetsCompat.Type.displayCutout()
      val bars = insets.getInsets(edges)
      content.setPadding(bars.left, bars.top, bars.right, bars.bottom)
      val remaining = WindowInsetsCompat.Builder(insets)
        .setInsets(WindowInsetsCompat.Type.statusBars(), Insets.NONE)
        .setInsets(WindowInsetsCompat.Type.navigationBars(), Insets.NONE)
        .setInsets(WindowInsetsCompat.Type.displayCutout(), Insets.NONE)
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        remaining.setDisplayCutout(null)
      }
      remaining.build()
    }
  }
}
