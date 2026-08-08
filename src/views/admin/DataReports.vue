<template>
  <div>
    <!-- 时间范围选择 -->
    <div class="flex items-center gap-3 mb-4">
      <button v-for="range in ranges" :key="range.value" @click="activeRange = range.value" class="px-4 py-2 rounded-lg text-sm" :class="activeRange === range.value ? 'bg-primary text-white' : 'bg-white dark:bg-dark-100 text-gray-600 dark:text-gray-400 hover:bg-gray-100'">{{ range.label }}</button>
      <div class="flex-1" />
      <ExportButton filename="运营数据报表" :data="exportData" />
    </div>

    <!-- 汇总数据 -->
    <div class="grid grid-cols-3 lg:grid-cols-6 gap-4 mb-6">
      <div v-for="metric in summaryMetrics" :key="metric.label" class="bg-white dark:bg-dark-100 rounded-xl p-4 shadow-sm">
        <p class="text-xs text-gray-500">{{ metric.label }}</p>
        <p class="text-xl font-bold text-gray-900 dark:text-white mt-1">{{ metric.value }}</p>
        <p class="text-xs mt-1" :class="metric.change >= 0 ? 'text-green-500' : 'text-red-500'">{{ metric.change >= 0 ? '↑' : '↓' }} {{ Math.abs(metric.change) }}%</p>
      </div>
    </div>

    <!-- 趋势图表区 -->
    <div class="grid lg:grid-cols-2 gap-6 mb-6">
      <div class="bg-white dark:bg-dark-100 rounded-xl p-5 shadow-sm">
        <h3 class="font-bold text-gray-900 dark:text-white mb-4">用户增长趋势</h3>
        <div class="space-y-2">
          <div v-for="item in reportData" :key="item.period" class="flex items-center gap-3">
            <span class="text-xs text-gray-400 w-20">{{ item.period }}</span>
            <div class="flex-1 h-6 bg-gray-100 dark:bg-dark-300 rounded-full overflow-hidden">
              <div class="h-full bg-gradient-to-r from-blue-400 to-primary rounded-full flex items-center justify-end pr-2" :style="{ width: (item.newUsers / maxUsers * 100) + '%' }">
                <span v-if="item.newUsers / maxUsers > 0.15" class="text-xs text-white">{{ item.newUsers }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
      <div class="bg-white dark:bg-dark-100 rounded-xl p-5 shadow-sm">
        <h3 class="font-bold text-gray-900 dark:text-white mb-4">营收趋势</h3>
        <div class="space-y-2">
          <div v-for="item in reportData" :key="item.period" class="flex items-center gap-3">
            <span class="text-xs text-gray-400 w-20">{{ item.period }}</span>
            <div class="flex-1 h-6 bg-gray-100 dark:bg-dark-300 rounded-full overflow-hidden">
              <div class="h-full bg-gradient-to-r from-green-400 to-emerald-500 rounded-full flex items-center justify-end pr-2" :style="{ width: (item.revenue / maxRevenue * 100) + '%' }">
                <span v-if="item.revenue / maxRevenue > 0.15" class="text-xs text-white">¥{{ item.revenue.toLocaleString() }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- 详细数据表 -->
    <div class="bg-white dark:bg-dark-100 rounded-xl shadow-sm overflow-hidden">
      <div class="p-4 border-b border-gray-100 dark:border-gray-700 flex items-center justify-between">
        <h3 class="font-bold text-gray-900 dark:text-white">详细数据</h3>
        <ExportButton filename="详细运营数据" :data="exportData" />
      </div>
      <table class="w-full text-sm">
        <thead class="bg-gray-50 dark:bg-dark-200">
          <tr>
            <th class="px-4 py-3 text-left text-gray-500">日期</th>
            <th class="px-4 py-3 text-right text-gray-500">新增用户</th>
            <th class="px-4 py-3 text-right text-gray-500">活跃用户</th>
            <th class="px-4 py-3 text-right text-gray-500">营收(¥)</th>
            <th class="px-4 py-3 text-right text-gray-500">圣力消耗</th>
            <th class="px-4 py-3 text-right text-gray-500">订单数</th>
            <th class="px-4 py-3 text-right text-gray-500">工具调用</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-gray-100 dark:divide-gray-700">
          <tr v-for="item in reportData" :key="item.period" class="hover:bg-gray-50 dark:hover:bg-dark-200">
            <td class="px-4 py-3 text-gray-700 dark:text-gray-300 font-medium">{{ item.period }}</td>
            <td class="px-4 py-3 text-right text-gray-600 dark:text-gray-400">{{ item.newUsers.toLocaleString() }}</td>
            <td class="px-4 py-3 text-right text-gray-600 dark:text-gray-400">{{ item.activeUsers.toLocaleString() }}</td>
            <td class="px-4 py-3 text-right text-green-600 font-medium">{{ item.revenue.toLocaleString() }}</td>
            <td class="px-4 py-3 text-right text-amber-600">{{ item.coinConsumed.toLocaleString() }}</td>
            <td class="px-4 py-3 text-right text-gray-600 dark:text-gray-400">{{ item.orders.toLocaleString() }}</td>
            <td class="px-4 py-3 text-right text-blue-600">{{ item.toolCalls.toLocaleString() }}</td>
          </tr>
        </tbody>
        <tfoot class="bg-gray-50 dark:bg-dark-200 font-semibold">
          <tr>
            <td class="px-4 py-3 text-gray-700 dark:text-gray-300">合计</td>
            <td class="px-4 py-3 text-right">{{ reportData.reduce((s, i) => s + i.newUsers, 0).toLocaleString() }}</td>
            <td class="px-4 py-3 text-right">-</td>
            <td class="px-4 py-3 text-right text-green-600">¥{{ reportData.reduce((s, i) => s + i.revenue, 0).toLocaleString() }}</td>
            <td class="px-4 py-3 text-right text-amber-600">{{ reportData.reduce((s, i) => s + i.coinConsumed, 0).toLocaleString() }}</td>
            <td class="px-4 py-3 text-right">{{ reportData.reduce((s, i) => s + i.orders, 0).toLocaleString() }}</td>
            <td class="px-4 py-3 text-right text-blue-600">{{ reportData.reduce((s, i) => s + i.toolCalls, 0).toLocaleString() }}</td>
          </tr>
        </tfoot>
      </table>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import type { ReportData } from '@/types'
import ExportButton from '@/components/ExportButton.vue'
import { adminApi } from '@/api'

const activeRange = ref('7d')
const ranges = [
  { label: '近7天', value: '7d' },
  { label: '近30天', value: '30d' },
  { label: '近90天', value: '90d' },
]

const reportData = ref<ReportData[]>([])

async function loadData() {
  try {
    const res = await adminApi.getDashboard()
    if (res.code === 0 && res.data?.trend) {
      const t = res.data.trend
      reportData.value = (t.dates || []).map((d: string, i: number) => ({
        period: d,
        newUsers: t.newUsers?.[i] || 0,
        activeUsers: t.activeUsers?.[i] || 0,
        revenue: t.revenue?.[i] || 0,
        coinConsumed: t.toolCalls?.[i] || 0,
        orders: 0,
        toolCalls: t.toolCalls?.[i] || 0,
      }))
    }
  } catch (e: any) { console.warn('[API] 加载报表数据失败:', e?.message) }
}

const maxUsers = computed(() => Math.max(...reportData.value.map(r => r.newUsers), 1))
const maxRevenue = computed(() => Math.max(...reportData.value.map(r => r.revenue), 1))

const summaryMetrics = computed(() => {
  const data = reportData.value
  const totalNewUsers = data.reduce((s, i) => s + i.newUsers, 0)
  const totalRevenue = data.reduce((s, i) => s + i.revenue, 0)
  const totalOrders = data.reduce((s, i) => s + i.orders, 0)
  const totalCoinConsumed = data.reduce((s, i) => s + i.coinConsumed, 0)
  const totalToolCalls = data.reduce((s, i) => s + i.toolCalls, 0)
  const avgActiveUsers = data.length > 0 ? Math.round(data.reduce((s, i) => s + i.activeUsers, 0) / data.length) : 0
  return [
    { label: '新增用户', value: totalNewUsers.toLocaleString(), change: 12.5 },
    { label: '日均活跃', value: avgActiveUsers.toLocaleString(), change: 8.3 },
    { label: '总营收', value: '¥' + totalRevenue.toLocaleString(), change: 15.2 },
    { label: '圣力消耗', value: totalCoinConsumed.toLocaleString(), change: 10.7 },
    { label: '订单数', value: totalOrders.toLocaleString(), change: -3.2 },
    { label: '工具调用', value: totalToolCalls.toLocaleString(), change: 18.9 },
  ]
})

const exportData = computed(() => reportData.value.map(r => ({
  '日期': r.period, '新增用户': r.newUsers, '活跃用户': r.activeUsers,
  '营收': r.revenue, '圣力消耗': r.coinConsumed, '订单数': r.orders, '工具调用': r.toolCalls
})))

onMounted(loadData)
</script>
