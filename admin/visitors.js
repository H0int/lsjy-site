
// ===== 访客中心模块 =====
(function() {
  'use strict';

  var API_BASE = (function() {
    var host = window.location.hostname;
    if (host === 'localhost' || host === '127.0.0.1') return 'http://localhost:3000/api/v1';
    if (host === 'h0int.github.io') return 'http://8.154.16.5:3000/api/v1';
    return 'https://' + host.replace('www.','').replace('m.','') + '/api/v1';
  })();

  // 访客中心页面渲染
  window.renderVisitors = function() {
    var html = '<div class="page-header"><h2><i class="fa-solid fa-users-viewfinder"></i> 访客中心</h2></div>';
    
    // 统计卡片
    html += '<div class="dash-grid" style="margin-bottom:20px;">';
    html += '<div class="dash-card" style="padding:16px;"><div style="font-size:13px;color:var(--text-dim);">总访客数</div><div id="v-total" style="font-size:28px;font-weight:700;color:var(--p);margin-top:4px;">--</div></div>';
    html += '<div class="dash-card" style="padding:16px;"><div style="font-size:13px;color:var(--text-dim);">今日访客</div><div id="v-today" style="font-size:28px;font-weight:700;color:var(--ok);margin-top:4px;">--</div></div>';
    html += '<div class="dash-card" style="padding:16px;"><div style="font-size:13px;color:var(--text-dim);">最近访问时间</div><div id="v-last" style="font-size:16px;font-weight:600;color:var(--cyan);margin-top:8px;">--</div></div>';
    html += '</div>';

    // 最近访客列表
    html += '<div class="card"><div class="card-body">';
    html += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">';
    html += '<h3 style="margin:0;font-size:15px;font-weight:600;"><i class="fa-solid fa-clock-rotate-left"></i> 最近访客</h3>';
    html += '<button class="admin-btn" onclick="VisitorsAPI.loadStats()" style="font-size:12px;"><i class="fa-solid fa-rotate"></i> 刷新</button>';
    html += '</div>';
    html += '<div id="visitors-list">加载中...</div>';
    html += '</div></div>';

    // 全部访客记录（分页）
    html += '<div class="card" style="margin-top:16px;"><div class="card-body">';
    html += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">';
    html += '<h3 style="margin:0;font-size:15px;font-weight:600;"><i class="fa-solid fa-list"></i> 全部访客记录</h3>';
    html += '<div id="visitors-pagination"></div>';
    html += '</div>';
    html += '<div id="visitors-all-list">加载中...</div>';
    html += '</div></div>';

    return html;
  };

  // 访客API
  window.VisitorsAPI = {
    currentPage: 1,
    
    loadStats: function() {
      fetch(API_BASE + '/visitors/stats')
        .then(function(r) { return r.json(); })
        .then(function(res) {
          var data = res.data || {};
          var totalEl = document.getElementById('v-total');
          var todayEl = document.getElementById('v-today');
          var lastEl = document.getElementById('v-last');
          if (totalEl) totalEl.textContent = data.totalVisitors || 0;
          if (todayEl) todayEl.textContent = data.todayVisitors || 0;
          if (lastEl) lastEl.textContent = data.lastVisitTime || '暂无记录';
          
          // 渲染最近访客
          VisitorsAPI.renderRecentVisitors(data.recentVisitors || []);
        })
        .catch(function(e) {
          var el = document.getElementById('visitors-list');
          if (el) el.innerHTML = '<div class="empty">加载失败: ' + e.message + '</div>';
        });
      
      // 同时加载全部记录
      VisitorsAPI.loadAll(1);
    },
    
    renderRecentVisitors: function(visitors) {
      var container = document.getElementById('visitors-list');
      if (!container) return;
      if (!visitors || visitors.length === 0) {
        container.innerHTML = '<div class="empty">暂无访客记录</div>';
        return;
      }
      
      var html = '<table class="data-table"><thead><tr>';
      html += '<th>#</th><th>IP地址</th><th>访问时间</th><th>访问页面</th><th>来源</th>';
      html += '</tr></thead><tbody>';
      
      visitors.forEach(function(v) {
        html += '<tr>';
        html += '<td>' + v.id + '</td>';
        html += '<td><code>' + (v.ip || 'unknown') + '</code></td>';
        html += '<td style="color:var(--cyan);font-weight:500;">' + (v.visitTimeFormatted || v.visitTime || '') + '</td>';
        html += '<td>' + (v.path || v.page || '/') + '</td>';
        html += '<td style="color:var(--text-dim);font-size:12px;">' + (v.userAgent || '').substring(0, 60) + '</td>';
        html += '</tr>';
      });
      
      html += '</tbody></table>';
      container.innerHTML = html;
    },
    
    loadAll: function(page) {
      VisitorsAPI.currentPage = page || 1;
      fetch(API_BASE + '/visitors/list?page=' + VisitorsAPI.currentPage + '&pageSize=15')
        .then(function(r) { return r.json(); })
        .then(function(res) {
          var data = res.data || {};
          var items = data.items || [];
          var total = data.total || 0;
          var container = document.getElementById('visitors-all-list');
          if (!container) return;
          
          if (!items || items.length === 0) {
            container.innerHTML = '<div class="empty">暂无访客记录</div>';
            return;
          }
          
          var html = '<table class="data-table"><thead><tr>';
          html += '<th>#</th><th>IP地址</th><th>访问时间</th><th>访问页面</th><th>来源</th><th>User-Agent</th>';
          html += '</tr></thead><tbody>';
          
          items.forEach(function(v) {
            html += '<tr>';
            html += '<td>' + v.id + '</td>';
            html += '<td><code>' + (v.ip || 'unknown') + '</code></td>';
            html += '<td style="color:var(--cyan);font-weight:500;">' + (v.visitTimeFormatted || v.visitTime || '') + '</td>';
            html += '<td>' + (v.path || v.page || '/') + '</td>';
            html += '<td style="color:var(--text-dim);">' + (v.referer || '-') + '</td>';
            html += '<td style="color:var(--text-dim);font-size:11px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + (v.userAgent || '') + '</td>';
            html += '</tr>';
          });
          
          html += '</tbody></table>';
          
          // 分页
          var totalPages = Math.ceil(total / 15);
          if (totalPages > 1) {
            html += '<div style="display:flex;justify-content:center;gap:8px;margin-top:12px;">';
            for (var p = 1; p <= Math.min(totalPages, 10); p++) {
              var active = p === VisitorsAPI.currentPage ? 'background:var(--p);color:#fff;' : '';
              html += '<button onclick="VisitorsAPI.loadAll(' + p + ')" style="padding:4px 10px;border:1px solid var(--border);border-radius:4px;cursor:pointer;' + active + '">' + p + '</button>';
            }
            html += '</div>';
          }
          
          container.innerHTML = html;
        })
        .catch(function(e) {
          var el = document.getElementById('visitors-all-list');
          if (el) el.innerHTML = '<div class="empty">加载失败: ' + e.message + '</div>';
        });
    }
  };

  // 注册路由
  if (typeof window.routes !== 'undefined') {
    window.routes.visitors = { render: window.renderVisitors, title: '访客中心' };
  }

  // 监听navigate事件
  var origNavigate = window.navigate;
  window.navigate = function(page) {
    if (origNavigate) origNavigate(page);
    if (page === 'visitors') {
      setTimeout(function() { VisitorsAPI.loadStats(); }, 100);
    }
  };

})();
