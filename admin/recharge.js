
// ===== 充值审批模块 =====
(function() {
  'use strict';

  // 充值审批页面渲染
  window.renderRecharge = function() {
    var html = '<div class="page-header"><h2><i class="fa-solid fa-money-check-dollar"></i> 充值审批</h2></div>';
    html += '<div class="card"><div class="card-body">';
    html += '<div class="tab-bar" style="margin-bottom:16px;">';
    html += '<div class="tab-item active" onclick="RechargeAPI.loadOrders(\'pending_review\')">待审核</div>';
    html += '<div class="tab-item" onclick="RechargeAPI.loadOrders(\'approved\')">已通过</div>';
    html += '<div class="tab-item" onclick="RechargeAPI.loadOrders(\'rejected\')">已拒绝</div>';
    html += '<div class="tab-item" onclick="RechargeAPI.loadOrders(\'all\')">全部</div>';
    html += '</div>';
    html += '<div id="recharge-list">加载中...</div>';
    html += '</div></div>';
    return html;
  };

  // 充值审批API
  window.RechargeAPI = {
    currentFilter: 'pending_review',
    
    loadOrders: function(status) {
      RechargeAPI.currentFilter = status;
      
      // 更新tab状态
      var tabs = document.querySelectorAll('.tab-bar .tab-item');
      tabs.forEach(function(t, i) {
        var statuses = ['pending_review', 'approved', 'rejected', 'all'];
        t.classList.toggle('active', statuses[i] === status);
      });
      
      fetch(APP.apiBase + '/payment/coin/orders')
        .then(function(r) { return r.json(); })
        .then(function(res) {
          var orders = res.data?.items || [];
          if (status !== 'all') {
            orders = orders.filter(function(o) { return o.status === status; });
          }
          RechargeAPI.renderOrders(orders);
        })
        .catch(function(e) {
          document.getElementById('recharge-list').innerHTML = '<div class="empty">加载失败: ' + e.message + '</div>';
        });
    },
    
    renderOrders: function(orders) {
      var container = document.getElementById('recharge-list');
      if (!orders || orders.length === 0) {
        container.innerHTML = '<div class="empty">暂无订单</div>';
        return;
      }
      
      var html = '<table class="data-table"><thead><tr>';
      html += '<th>订单号</th><th>用户</th><th>金额</th><th>圣点</th><th>支付方式</th><th>状态</th><th>截图</th><th>时间</th><th>操作</th>';
      html += '</tr></thead><tbody>';
      
      orders.forEach(function(o) {
        var statusBadge = '';
        if (o.status === 'pending_payment') statusBadge = '<span class="badge badge-w">待付款</span>';
        else if (o.status === 'pending_review') statusBadge = '<span class="badge badge-b">待审核</span>';
        else if (o.status === 'approved') statusBadge = '<span class="badge badge-g">已通过</span>';
        else if (o.status === 'rejected') statusBadge = '<span class="badge badge-r">已拒绝</span>';
        
        var payMethod = o.paymentMethod === 'wechat' ? '💚微信' : o.paymentMethod === 'alipay' ? '💙支付宝' : '🐧QQ';
        
        var screenshot = o.screenshotUrl ? '<a href="' + o.screenshotUrl + '" target="_blank" class="btn-sm btn-blue">查看</a>' : '<span style="color:var(--text-dim)">无</span>';
        
        var actions = '';
        if (o.status === 'pending_review') {
          actions = '<button class="btn-sm btn-green" onclick="RechargeAPI.approve(' + o.id + ',\'approve\')">通过</button> ';
          actions += '<button class="btn-sm btn-red" onclick="RechargeAPI.approve(' + o.id + ',\'reject\')">拒绝</button>';
        } else {
          actions = '<span style="color:var(--text-dim)">-</span>';
        }
        
        html += '<tr>';
        html += '<td>' + (o.orderNo || '') + '</td>';
        html += '<td>' + (o.username || '') + '</td>';
        html += '<td style="color:var(--amber);">¥' + o.price + '</td>';
        html += '<td style="color:var(--cyan);">' + o.coinAmount + '</td>';
        html += '<td>' + payMethod + '</td>';
        html += '<td>' + statusBadge + '</td>';
        html += '<td>' + screenshot + '</td>';
        html += '<td>' + (o.createdAt || '').substring(0, 16).replace('T', ' ') + '</td>';
        html += '<td>' + actions + '</td>';
        html += '</tr>';
      });
      
      html += '</tbody></table>';
      container.innerHTML = html;
    },
    
    approve: function(orderId, action) {
      var msg = action === 'approve' ? '确认通过此充值订单？通过后用户将获得相应圣点。' : '确认拒绝此充值订单？';
      if (!confirm(msg)) return;
      
      fetch(APP.apiBase + '/payment/coin/approve/' + orderId, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: action })
      })
      .then(function(r) { return r.json(); })
      .then(function(res) {
        if (res.code === 0) {
          toast(res.message, 'success');
          RechargeAPI.loadOrders(RechargeAPI.currentFilter);
        } else {
          toast(res.message || '操作失败', 'error');
        }
      })
      .catch(function(e) {
        toast('请求失败: ' + e.message, 'error');
      });
    }
  };

  // 注册路由
  if (typeof window.routes !== 'undefined') {
    window.routes.recharge = { render: window.renderRecharge, title: '充值审批' };
  }

  // 监听navigate事件，自动加载订单
  var origNavigate = window.navigate;
  window.navigate = function(page) {
    if (origNavigate) origNavigate(page);
    if (page === 'recharge') {
      setTimeout(function() { RechargeAPI.loadOrders('pending_review'); }, 100);
    }
  };

})();
