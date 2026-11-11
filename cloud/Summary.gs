/* Build a formula-driven Summary tab. Does not change Reports or the receiver.
 * Run setupDnsSummary() once in the same Apps Script project as Code.gs.
 * Re-running rebuilds only a Summary tab previously created by this script.
 */

const SUMMARY_TITLE = 'DNS Checker — сводка результатов';
const SUMMARY_FIRST_DNS_ROW = 9;
const SUMMARY_DNS_ROWS = 100;
const SUMMARY_FIRST_PAIR_ROW = 17;
const SUMMARY_PAIR_ROWS = 60;
const SUMMARY_PAIR_LAST_DATA_ROW = 10000;

function setupDnsSummary() {
  const sheetId = PropertiesService.getScriptProperties().getProperty('SHEET_ID');
  if (!sheetId) throw new Error('SHEET_ID is not configured');
  const book = SpreadsheetApp.openById(sheetId);
  if (!book.getSheetByName('Reports')) throw new Error('Reports sheet not found');

  let sheet = book.getSheetByName('Summary');
  if (sheet && sheet.getRange('A1').getValue() !== SUMMARY_TITLE) {
    throw new Error('Summary already exists and was not created by this script');
  }
  sheet = sheet || book.insertSheet('Summary');
  sheet.clear();
  sheet.clearConditionalFormatRules();
  sheet.setHiddenGridlines(true);

  buildSummaryTop_(sheet);
  buildDnsTable_(sheet);
  buildBreakdowns_(sheet);
  buildPairTable_(sheet);
  formatSummary_(sheet);
  SpreadsheetApp.flush();

  const result = {
    ok: true,
    sheet: 'Summary',
    reports: sheet.getRange('B4').getValue(),
    dnsFormula: sheet.getRange('A9').getFormula(),
    pairFormula: sheet.getRange('K17').getFormula()
  };
  Logger.log(JSON.stringify(result));
  return result;
}

function buildSummaryTop_(sheet) {
  sheet.getRange('A1:I1').merge().setValue(SUMMARY_TITLE);
  sheet.getRange('A2:I2').merge().setValue(
    'Обновляется автоматически по листу Reports. Это прошлые результаты, а не гарантия для нового абонента.');
  sheet.getRange('K1:T1').merge().setValue('Как считать');
  sheet.getRange('K2:T3').merge().setValue(
    'Доля успеха = «Вход заработал» / все известные результаты. «Неизвестно» не участвует в доле. ' +
    'DNS учитывается и как основной, и как второй. Пары показаны в порядке ввода. Дата — последний created_at из Reports.');

  const labels = [
    ['A4', 'Всего отчётов'], ['C4', 'Вход заработал'], ['E4', 'Та же ошибка'],
    ['G4', 'Другая ошибка'], ['A5', 'Неизвестно'], ['C5', 'Доля успеха'], ['E5', 'Последний отчёт']
  ];
  labels.forEach(function(item) { sheet.getRange(item[0]).setValue(item[1]); });
  sheet.getRange('B4').setFormula('=COUNTIF(Reports!A2:A,"<>")');
  sheet.getRange('D4').setFormula('=COUNTIF(Reports!E2:E,"worked")');
  sheet.getRange('F4').setFormula('=COUNTIF(Reports!E2:E,"same_error")');
  sheet.getRange('H4').setFormula('=COUNTIF(Reports!E2:E,"different_error")');
  sheet.getRange('B5').setFormula('=COUNTIF(Reports!E2:E,"unknown")');
  sheet.getRange('D5').setFormula('=IFERROR(D4/(B4-B5),0)');
  sheet.getRange('F5:I5').merge().setFormula(
    '=IFERROR(INDEX(SORT(FILTER(Reports!C2:C,Reports!C2:C<>""),1,FALSE),1),"")');
}

function buildDnsTable_(sheet) {
  sheet.getRange('A7:I7').merge().setValue('Результаты по DNS');
  sheet.getRange('A8:I8').setValues([[
    'DNS', 'Отчётов', 'Заработал', 'Та же ошибка', 'Другая ошибка',
    'Неизвестно', 'Известных', 'Доля успеха', 'Последний отчёт'
  ]]);
  sheet.getRange('A9').setFormula(
    '=SORT(UNIQUE(FILTER({Reports!H2:H;Reports!I2:I},{Reports!H2:H;Reports!I2:I}<>"")))');

  for (let row = SUMMARY_FIRST_DNS_ROW; row < SUMMARY_FIRST_DNS_ROW + SUMMARY_DNS_ROWS; row++) {
    const dns = '$A' + row;
    sheet.getRange(row, 2).setFormula(
      '=IF(' + dns + '="","",COUNTIF(Reports!$H$2:$H,' + dns + ')+COUNTIF(Reports!$I$2:$I,' + dns + '))');
    ['worked', 'same_error', 'different_error', 'unknown'].forEach(function(outcome, index) {
      sheet.getRange(row, 3 + index).setFormula(
        '=IF(' + dns + '="","",COUNTIFS(Reports!$H$2:$H,' + dns + ',Reports!$E$2:$E,"' + outcome +
        '")+COUNTIFS(Reports!$I$2:$I,' + dns + ',Reports!$E$2:$E,"' + outcome + '"))');
    });
    sheet.getRange(row, 7).setFormula('=IF(' + dns + '="","",SUM(C' + row + ':E' + row + '))');
    sheet.getRange(row, 8).setFormula('=IF(' + dns + '="","",IFERROR(C' + row + '/G' + row + ',0))');
    sheet.getRange(row, 9).setFormula(
      '=IF(' + dns + '="","",IFERROR(INDEX(SORT(FILTER(Reports!$C$2:$C,' +
      '(Reports!$H$2:$H=' + dns + ')+(Reports!$I$2:$I=' + dns + ')),1,FALSE),1),""))');
  }
}

function buildBreakdowns_(sheet) {
  const groups = [
    {
      column: 11, title: 'По типу сети', sourceColumn: 'J',
      rows: [['Офис', 'office'], ['Дом', 'home'], ['VPN', 'vpn'], ['Другое', 'other']]
    },
    {
      column: 16, title: 'Где меняли DNS', sourceColumn: 'G',
      rows: [['Консоль', 'console'], ['Роутер', 'router'], ['Оба места', 'both'], ['Неизвестно', 'unknown']]
    }
  ];
  groups.forEach(function(group) {
    const start = group.column;
    sheet.getRange(7, start, 1, 5).merge().setValue(group.title);
    sheet.getRange(8, start, 1, 5).setValues([[
      'Значение', 'Отчётов', 'Заработал', 'Неизвестно', 'Доля успеха'
    ]]);
    group.rows.forEach(function(item, index) {
      const row = 9 + index;
      sheet.getRange(row, start).setValue(item[0]);
      sheet.getRange(row, start + 1).setFormula(
        '=COUNTIF(Reports!$' + group.sourceColumn + '$2:$' + group.sourceColumn + ',"' + item[1] + '")');
      sheet.getRange(row, start + 2).setFormula(
        '=COUNTIFS(Reports!$' + group.sourceColumn + '$2:$' + group.sourceColumn + ',"' + item[1] +
        '",Reports!$E$2:$E,"worked")');
      sheet.getRange(row, start + 3).setFormula(
        '=COUNTIFS(Reports!$' + group.sourceColumn + '$2:$' + group.sourceColumn + ',"' + item[1] +
        '",Reports!$E$2:$E,"unknown")');
      const reports = String.fromCharCode(65 + start) + row;
      const worked = String.fromCharCode(66 + start) + row;
      const unknown = String.fromCharCode(67 + start) + row;
      sheet.getRange(row, start + 4).setFormula(
        '=IFERROR(' + worked + '/(' + reports + '-' + unknown + '),0)');
    });
  });
}

function buildPairTable_(sheet) {
  sheet.getRange('K15:R15').merge().setValue('Пары DNS (в порядке ввода)');
  sheet.getRange('K16:R16').setValues([[
    'DNS 1 | DNS 2', 'Отчётов', 'Заработал', 'Та же ошибка',
    'Другая ошибка', 'Неизвестно', 'Доля успеха', 'Последний отчёт'
  ]]);
  sheet.getRange('K17').setFormula(
    '=SORT(UNIQUE(FILTER(Reports!H2:H&" | "&Reports!I2:I,Reports!H2:H<>"")))');
  const last = SUMMARY_PAIR_LAST_DATA_ROW;

  for (let row = SUMMARY_FIRST_PAIR_ROW; row < SUMMARY_FIRST_PAIR_ROW + SUMMARY_PAIR_ROWS; row++) {
    const pair = '$K' + row;
    const pairRange = 'Reports!$H$2:$H$' + last + '&" | "&Reports!$I$2:$I$' + last;
    sheet.getRange(row, 12).setFormula(
      '=IF(' + pair + '="","",SUMPRODUCT((' + pairRange + '=' + pair + ')*1))');
    ['worked', 'same_error', 'different_error', 'unknown'].forEach(function(outcome, index) {
      sheet.getRange(row, 13 + index).setFormula(
        '=IF(' + pair + '="","",SUMPRODUCT((' + pairRange + '=' + pair +
        ')*(Reports!$E$2:$E$' + last + '="' + outcome + '")))');
    });
    sheet.getRange(row, 17).setFormula(
      '=IF(' + pair + '="","",IFERROR(M' + row + '/(L' + row + '-P' + row + '),0))');
    sheet.getRange(row, 18).setFormula(
      '=IF(' + pair + '="","",IFERROR(INDEX(SORT(FILTER(Reports!$C$2:$C$' + last + ',' +
      pairRange + '=' + pair + '),1,FALSE),1),""))');
  }
}

function formatSummary_(sheet) {
  sheet.setFrozenRows(8);
  sheet.getRange('A1:T1').setFontSize(15).setFontWeight('bold').setFontColor('#ffffff')
    .setBackground('#a95336');
  sheet.getRange('A2:T3').setFontSize(10).setFontColor('#65625d').setWrap(true);
  sheet.getRange('A4:H5').setFontWeight('bold');
  sheet.getRange('B4:B5').setFontSize(13).setFontColor('#a95336');
  sheet.getRange('D4:D5').setFontSize(13).setFontColor('#a95336');
  sheet.getRange('F4:H4').setFontSize(13).setFontColor('#a95336');
  sheet.getRange('A7:I7').setBackground('#f2e7e1').setFontWeight('bold');
  sheet.getRange('K7:O7').setBackground('#f2e7e1').setFontWeight('bold');
  sheet.getRange('P7:T7').setBackground('#f2e7e1').setFontWeight('bold');
  sheet.getRange('K15:R15').setBackground('#f2e7e1').setFontWeight('bold');
  sheet.getRange('A8:I8').setBackground('#3f3d39').setFontColor('#ffffff').setFontWeight('bold');
  sheet.getRange('K8:O8').setBackground('#3f3d39').setFontColor('#ffffff').setFontWeight('bold');
  sheet.getRange('P8:T8').setBackground('#3f3d39').setFontColor('#ffffff').setFontWeight('bold');
  sheet.getRange('K16:R16').setBackground('#3f3d39').setFontColor('#ffffff').setFontWeight('bold');
  sheet.getRange('D5').setNumberFormat('0.0%');
  sheet.getRange('H9:H108').setNumberFormat('0.0%');
  sheet.getRange('O9:O12').setNumberFormat('0.0%');
  sheet.getRange('T9:T12').setNumberFormat('0.0%');
  sheet.getRange('Q17:Q76').setNumberFormat('0.0%');
  sheet.getRange('A9:T108').setVerticalAlignment('middle');
  sheet.getRange('A1:T108').setFontFamily('Arial');
  sheet.setColumnWidth(1, 165);
  sheet.setColumnWidths(2, 7, 92);
  sheet.setColumnWidth(9, 170);
  sheet.setColumnWidth(10, 24);
  sheet.setColumnWidth(11, 245);
  sheet.setColumnWidths(12, 6, 92);
  sheet.setColumnWidth(18, 170);
  sheet.setColumnWidths(19, 2, 92);
  sheet.setRowHeight(2, 30);
  sheet.setRowHeight(3, 30);

  const rules = [
    {range: 'H9:H108'}, {range: 'O9:O12'}, {range: 'T9:T12'}, {range: 'Q17:Q76'}
  ].map(function(item) {
    return SpreadsheetApp.newConditionalFormatRule()
      .setGradientMinpoint('#f4cccc')
      .setGradientMidpointWithValue('#fff2cc', SpreadsheetApp.InterpolationType.NUMBER, '0.5')
      .setGradientMaxpoint('#d9ead3')
      .setRanges([sheet.getRange(item.range)])
      .build();
  });
  sheet.setConditionalFormatRules(rules);
}
