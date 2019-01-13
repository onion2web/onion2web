// Memory pooling for frequently cycled data
package onion2web

type Pool struct {
	Pool chan interface{}
	Maker func() interface{}
}

func (bp *Pool) Get() (b interface{}) {
	select {
	case b = <-bp.Pool:
	default:
		b = bp.Maker()
	}
	return
}

func (bp *Pool) Put(b interface{}) {
	if b == nil {
		return
	}
	select {
	case bp.Pool <- b:
	default:
	}
}

func (p *Pool) Init(n int, fn func() interface{}) (*Pool) {
	p.Pool = make(chan interface{}, n)
	p.Maker = fn
	return p
}

func MakePool(n int, fn func() interface{}) *Pool {
	return (&Pool{}).Init(n, fn)
}




type BufPool struct {
	Pool chan []byte
	Size int
}

func (bp *BufPool) Get() (b []byte) {
	select {
	case b = <-bp.Pool:
	default:
		b = make([]byte, bp.Size)
	}
	return
}

func (bp *BufPool) Put(b []byte) {
	if b == nil {
		return
	}
	select {
	case bp.Pool <- b:
	default:
	}
}

func (bp *BufPool) Init(n int, size int) *BufPool {
	bp.Pool = make(chan[]byte, n)
	bp.Size = size
	return bp
}

func MakeBufPool(n int, size int) (*BufPool) {
	return (&BufPool{}).Init(n, size)
}