require('dotenv').config()
const express = require('express')
const cors = require('cors')
const crypto = require('crypto')
const fetch = require('node-fetch')

const app = express()
const PORT = process.env.PORT || 3001

// =============================================
// MIDDLEWARE
// =============================================

// CORS — permite o frontend acessar o backend
app.use(cors({
  origin: [
    process.env.FRONTEND_URL || 'http://localhost:3000',
    // Adicione aqui outras origens permitidas se necessário
    // 'https://www.seusite.com.br'
  ],
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type']
}))

// Webhook precisa do body cru para validar HMAC
app.use('/api/webhook', express.raw({ type: 'application/json' }))
app.use(express.json())

// =============================================
// VARIÁVEIS DE CONFIGURAÇÃO
// =============================================
const NEXUSPAG_API_KEY = process.env.NEXUSPAG_API_KEY
const NEXUSPAG_WEBHOOK_SECRET = process.env.NEXUSPAG_WEBHOOK_SECRET
const NEXUSPAG_BASE_URL = process.env.NEXUSPAG_BASE_URL || 'https://nexuspag.com'

// Guarda pedidos em memória (em produção use um banco de dados)
// Estrutura: { [externalId]: { status, nome, total, items, criadoEm } }
const pedidos = {}

// =============================================
// ROTA: CRIAR COBRANÇA PIX
// POST /api/pix/criar
// =============================================
app.post('/api/pix/criar', async (req, res) => {
  try {
    const { amount, description, external_id, nome, telefone, endereco, mensagem, items } = req.body

    // Validações básicas
    if (!amount || amount <= 0) {
      return res.status(400).json({ erro: 'Valor inválido' })
    }
    if (!external_id) {
      return res.status(400).json({ erro: 'external_id obrigatório' })
    }
    if (!NEXUSPAG_API_KEY) {
      return res.status(500).json({ erro: 'API Key NexusPag não configurada no servidor' })
    }

    // Monta a URL do webhook deste próprio servidor
    // Quando o Railway fizer deploy, use a URL pública que ele gerar
    const webhookUrl = process.env.RAILWAY_PUBLIC_DOMAIN
      ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}/api/webhook/nexuspag`
      : null // Em desenvolvimento local, o webhook não chegará (use ngrok para testar)

    // Chama a API da NexusPag
    const nexusResponse = await fetch(`${NEXUSPAG_BASE_URL}/api/pix/create`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': NEXUSPAG_API_KEY
      },
      body: JSON.stringify({
        amount: parseFloat(amount.toFixed(2)),
        description: description || `Pedido ChocoCesta #${external_id}`,
        external_id,
        ...(webhookUrl && { webhook_url: webhookUrl })
      })
    })

    const nexusData = await nexusResponse.json()

    if (!nexusResponse.ok) {
      console.error('Erro NexusPag:', nexusData)
      return res.status(nexusResponse.status).json({
        erro: nexusData.message || nexusData.error || 'Erro ao criar cobrança Pix',
        detalhes: nexusData
      })
    }

    // Salva o pedido localmente
    pedidos[external_id] = {
      status: 'aguardando',
      pixId: nexusData.id || nexusData.txid,
      nome,
      telefone,
      endereco,
      mensagem,
      items,
      total: amount,
      criadoEm: new Date().toISOString()
    }

    console.log(`✅ Pix criado: ${external_id} | R$ ${amount} | ${nome}`)

    // Retorna os dados do Pix para o frontend
    res.json({
      sucesso: true,
      pix: nexusData
    })

  } catch (err) {
    console.error('Erro ao criar Pix:', err)
    res.status(500).json({ erro: 'Erro interno do servidor', detalhes: err.message })
  }
})

// =============================================
// ROTA: CONSULTAR STATUS DO PIX
// GET /api/pix/status/:id
// =============================================
app.get('/api/pix/status/:id', async (req, res) => {
  try {
    const { id } = req.params

    if (!NEXUSPAG_API_KEY) {
      return res.status(500).json({ erro: 'API Key NexusPag não configurada' })
    }

    const nexusResponse = await fetch(`${NEXUSPAG_BASE_URL}/api/pix/${id}`, {
      headers: { 'x-api-key': NEXUSPAG_API_KEY }
    })

    if (!nexusResponse.ok) {
      return res.status(nexusResponse.status).json({ erro: 'Pix não encontrado' })
    }

    const data = await nexusResponse.json()

    res.json({
      id: data.id || data.txid,
      status: data.status,
      valor: data.amount || data.valor,
      pago: isPago(data.status)
    })

  } catch (err) {
    console.error('Erro ao consultar Pix:', err)
    res.status(500).json({ erro: 'Erro ao consultar status' })
  }
})

// Verifica se o status indica pagamento confirmado
function isPago(status) {
  if (!status) return false
  const s = status.toString().toLowerCase()
  return ['paid', 'confirmed', 'completed', 'approved', 'payment.confirmed'].some(v => s.includes(v))
}

// =============================================
// ROTA: WEBHOOK NEXUSPAG
// POST /api/webhook/nexuspag
// =============================================
app.post('/api/webhook/nexuspag', (req, res) => {
  try {
    // Valida assinatura HMAC da NexusPag
    // Formato do header: "t=TIMESTAMP,v1=ASSINATURA"
    if (NEXUSPAG_WEBHOOK_SECRET) {
      const sig = req.headers['x-nexuspag-signature']

      if (!sig) {
        console.warn('⚠️  Webhook sem assinatura — rejeitado')
        return res.status(401).send('Unauthorized')
      }

      const ts = sig.split(',')[0].slice(2)        // extrai o timestamp
      const v1 = sig.split(',')[1].slice(3)        // extrai o hash

      const rawBody = req.body.toString('utf8')
      const msg = `${ts}.${rawBody}`

      const expected = crypto
        .createHmac('sha256', NEXUSPAG_WEBHOOK_SECRET)
        .update(msg)
        .digest('hex')

      if (!crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(v1))) {
        console.warn('⚠️  Assinatura inválida — webhook rejeitado')
        return res.status(401).send('Unauthorized')
      }
    }

    // Responde 200 após validar
    res.status(200).send('OK')

    const evento = JSON.parse(req.body.toString('utf8'))
    console.log('📥 Webhook recebido:', JSON.stringify(evento, null, 2))

    const tipo = evento.event || evento.type || ''
    const dados = evento.data || evento

    if (tipo === 'payment.confirmed' || isPago(dados.status)) {
      const externalId = dados.external_id || dados.externalId
      const pixId = dados.id || dados.txid

      console.log(`💚 Pagamento confirmado! external_id: ${externalId} | pix_id: ${pixId}`)

      // Atualiza o pedido
      if (externalId && pedidos[externalId]) {
        pedidos[externalId].status = 'pago'
        pedidos[externalId].pagoEm = new Date().toISOString()
        pedidos[externalId].pixId = pixId
        console.log(`📦 Pedido ${externalId} marcado como PAGO`)
        console.log(`   Cliente: ${pedidos[externalId].nome}`)
        console.log(`   Total:   R$ ${pedidos[externalId].total}`)
        console.log(`   Items:   ${JSON.stringify(pedidos[externalId].items)}`)
      }

      // 👉 Aqui você pode adicionar:
      // - Envio de WhatsApp/SMS para o cliente
      // - Envio de e-mail de confirmação
      // - Salvar em banco de dados
      // - Notificar painel administrativo
    }

  } catch (err) {
    console.error('Erro ao processar webhook:', err)
  }
})

// =============================================
// ROTA: LISTAR PEDIDOS (painel simples)
// GET /api/pedidos
// =============================================
app.get('/api/pedidos', (req, res) => {
  // Em produção, proteja esta rota com autenticação!
  const lista = Object.entries(pedidos).map(([id, p]) => ({
    external_id: id,
    ...p
  })).sort((a, b) => new Date(b.criadoEm) - new Date(a.criadoEm))

  res.json({ total: lista.length, pedidos: lista })
})

// =============================================
// ROTA: HEALTH CHECK
// GET /
// =============================================
app.get('/', (req, res) => {
  res.json({
    status: 'ok',
    servico: 'ChocoCesta Backend',
    versao: '1.0.0',
    timestamp: new Date().toISOString()
  })
})

// =============================================
// INICIA O SERVIDOR
// =============================================
app.listen(PORT, () => {
  console.log(``)
  console.log(`🍫 ChocoCesta Backend rodando na porta ${PORT}`)
  console.log(`   Ambiente: ${process.env.NODE_ENV || 'development'}`)
  console.log(`   NexusPag: ${NEXUSPAG_API_KEY ? '✅ API Key configurada' : '❌ API Key NÃO configurada'}`)
  console.log(`   Webhook:  ${NEXUSPAG_WEBHOOK_SECRET ? '✅ HMAC configurado' : '⚠️  Webhook secret não configurado'}`)
  console.log(``)
})
