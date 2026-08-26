import 'package:flutter_test/flutter_test.dart';
import 'package:blockvote_india/main.dart';

void main() {
  testWidgets('App renders splash screen', (WidgetTester tester) async {
    await tester.pumpWidget(const BlockVoteApp());
    expect(find.text('BlockVote'), findsOneWidget);
  });
}
