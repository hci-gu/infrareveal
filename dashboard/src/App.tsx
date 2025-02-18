import { useCurrentFrame } from 'remotion'
import { Player } from '@remotion/player'
import useWindowSize from './hooks/useWindowSize'
import { useEffect } from 'react'
import { getPackets } from './pocketbase'
import { actions, Packet, Start, world } from './ecs'
import { useActions, useQuery } from 'koota/react'
import Timeline from './components/Timeline'

const Content = () => {
  const frame = useCurrentFrame()

  return (
    <>
      <div className="flex justify-center items-center h-full w-full">
        <h1 className="text-white text-4xl font-bold">{frame}</h1>
        <Timeline />
      </div>
    </>
  )
}

const PlayerWrapper = () => {
  const { spawnPacket } = useActions(actions)
  const packets = useQuery(Packet, Start)
  const { width, height } = useWindowSize()

  useEffect(() => {
    getPackets().then((packets) => {
      packets.forEach((packet) => spawnPacket(packet))
    })

    return () => {
      packets.forEach((entity) => entity.destroy())
    }
  }, [])

  if (!packets.length) {
    return <div>Loading...</div>
  }

  const dates = packets
    .map((entity) => entity.get(Start)?.value)
    .filter((d) => d) as Date[]
  const minDate = Math.min(...dates.map((d) => d.getTime()))
  const maxDate = Math.max(...dates.map((d) => d.getTime()))

  const totalSeconds = (maxDate - minDate) / 1000

  return (
    <Player
      component={Content}
      controls
      autoPlay
      spaceKeyToPlayOrPause
      durationInFrames={Math.round(totalSeconds) * 30}
      fps={30}
      compositionWidth={width}
      compositionHeight={height}
      style={{
        width: '100vw',
        height: '100vh',
        backgroundColor: 'black',
      }}
    />
  )
}

function App() {
  return <PlayerWrapper />
}

export default App
