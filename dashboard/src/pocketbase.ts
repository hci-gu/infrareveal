import Pocketbase from 'pocketbase'

const pb = new Pocketbase('http://192.168.10.200:8090')
pb.admins.authWithPassword('admin@email.com', 'password123')

export type Packet = {
  id: string
  session: string
  host: string
  client_ip: string
  lat: number
  lon: number
  country: string
  city: string
}

export const getPackets = async () => {
  const result = (await pb.collection('packets').getFullList()) as Packet[]

  // console.log(result)

  return result
}
