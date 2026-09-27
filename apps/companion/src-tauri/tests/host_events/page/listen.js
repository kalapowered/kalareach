// Listens for the host's events the way the interface does, through the event API's `listen` on
// the backend's event name, and says what it heard in the window's title, which the check reads
// back. The title changes one at a time, in the order the events arrived.
const { listen } = window.__TAURI__.event
const shown = window.__TAURI__.window.getCurrentWindow()
const heard = []
let told = Promise.resolve()
const tell = (title) => {
  told = told.then(() => shown.setTitle(title))
}
listen('kr://event', (published) => {
  heard.push(published.payload)
  tell(JSON.stringify(heard))
}).then(
  () => tell('listening'),
  (refused) => tell(`refused: ${String(refused)}`)
)
