import { End, Start } from '@/ecs'
import { useQuery } from 'koota/react'

export default function Timeline() {
  const items = useQuery(Start, End)

  return (
    <div className="bg-white p-4">
      {items.map((item, i) => (
        <div key={i}>
          {/* <h1>{item.id}</h1> */}
          <p>{item.get(Start)?.value.toDateString()}</p>
          <p>{item.get(End)?.value.toDateString()}</p>
        </div>
      ))}
    </div>
  )
}
