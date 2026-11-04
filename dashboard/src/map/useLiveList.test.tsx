// @vitest-environment jsdom
import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { expect, it, vi } from 'vitest'
import { useLiveList } from './useLiveList'
import { BackToLatest } from './BackToLatest'

Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true })
it('paces reordering, holds rows while scrolling or focusing, and returns to the newest order', async () => {
  const container = document.createElement('div'); document.body.append(container)
  const root = createRoot(container)
  const scrollTo = vi.fn()
  function Probe({ ids, time, scope = 'session' }: { ids: string[]; time: number; scope?: string }) {
    const { items: orderedItems, scrollRef: listRef, paused: listPaused, back: resumeList, onScroll: scrollList, pause: pauseList } = useLiveList(ids.map(id => ({ id })), scope, time)
    return <><BackToLatest paused={listPaused} onClick={resumeList} /><div ref={listRef} onScroll={scrollList} onFocusCapture={pauseList} data-list>{orderedItems.map(item => <button key={item.id}>{item.id}</button>)}</div></>
  }
  const render = async (ids: string[], time: number, scope?: string) => act(() => root.render(<Probe ids={ids} time={time} scope={scope} />))
  const order = () => [...container.querySelectorAll('[data-list] button')].map(node => node.textContent)
  try {
    await render(['old','new'], 1000)
    const list = container.querySelector<HTMLDivElement>('[data-list]')!
    list.scrollTo = scrollTo
    await render(['new','old'], 1500)
    expect(order()).toEqual(['old','new'])
    await render(['new','old'], 2000)
    expect(order()).toEqual(['new','old'])
    await act(() => { list.scrollTop = 100; list.dispatchEvent(new Event('scroll', { bubbles: true })) })
    await render(['old','new'], 3000)
    expect(order()).toEqual(['new','old'])
    await act(() => container.querySelector<HTMLButtonElement>('.atlas-back-latest')!.click())
    expect(order()).toEqual(['old','new'])
    expect(scrollTo).toHaveBeenCalledWith({ top: 0, left: 0 })
    const selected = list.querySelector<HTMLButtonElement>('button')!
    await act(() => selected.focus())
    await render(['new','old','newest'], 4000)
    expect(order()).toEqual(['old','new','newest'])
    expect(document.activeElement).toBe(selected)
    await render(['newest','new','old'], 4000, 'other-direction')
    expect(order()).toEqual(['newest','new','old'])
  } finally { await act(() => root.unmount()); container.remove() }
})
