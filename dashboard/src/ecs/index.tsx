import { createActions, relation, trait, World } from 'koota'
import { createWorld } from 'koota'

export const world = createWorld()

export const Packet = trait({})

export const Start = trait({
  value: new Date(),
})

export const End = trait({
  value: new Date(),
})

export const isActive = trait()

export const DataFor = relation({ autoRemoveTarget: true })

export const actions = createActions((world: World) => ({
  spawnPacket: (packet: any) => {
    const entity = world.spawn(Packet)

    const start = new Date(packet.created)
    // ends 4 seconds after start
    const end = new Date(start.getTime() + 4000)
    entity.add(Start({ value: start }))
    entity.add(End({ value: end }))

    return entity
  },
}))
